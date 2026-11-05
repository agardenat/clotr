package access

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

var shells = []string{"sh", "bash", "ash", "dash"}

func ShellScript(argv []string) (string, bool) {
	if len(argv) == 3 && slices.Contains(shells, path.Base(argv[0])) && argv[1] == "-c" {
		return argv[2], true
	}
	return "", false
}

func ReadOnly(argv []string) error {
	return ReadOnlyTrusting(argv, nil)
}

func ReadOnlyTrusting(argv []string, trusted []string) error {
	return ReadOnlyAllowing(argv, trusted, nil)
}

func ReadOnlyAllowing(argv []string, trusted []string, rules *Commands) error {
	if err := CheckArgv(argv); err != nil {
		return err
	}
	if err := sensitive(strings.Join(argv, " ")); err != nil {
		return err
	}
	args := make([]arg, len(argv))
	for i, a := range argv {
		args[i] = arg{a, true}
	}
	return checkCall(args, trusted, rules)
}

func sudoLen(args []arg) int {
	n := 0
	for n < len(args) && args[n].lit && (args[n].s == "sudo" || args[n].s == "/usr/bin/sudo") {
		n++
		if n < len(args) && args[n].lit && args[n].s == "-n" {
			n++
		}
	}
	return n
}

func checkCall(args []arg, trusted []string, rules *Commands) error {
	if n := sudoLen(args); n > 0 {
		args = args[n:]
		if len(args) == 0 {
			return fmt.Errorf("sudo sans commande")
		}
		if name := args[0].s; args[0].lit && (strings.HasPrefix(name, "-") || strings.Contains(name, "=")) {
			return fmt.Errorf("sudo %s : seule l'option -n est admise", name)
		}
	}
	words := make([]string, len(args))
	literal := true
	for i, a := range args {
		words[i] = a.s
		literal = literal && a.lit
	}
	if literal {
		if script, ok := ShellScript(words); ok {
			return readOnlyScript(script, trusted, rules)
		}
		switch rules.Check(words) {
		case Denied:
			return fmt.Errorf("%s : refusée par les motifs deny", Display(words))
		case Allowed:
			return nil
		}
	}
	if err := readOnlyCall(args); err != nil && !trustedCall(args, trusted) {
		return err
	}
	return nil
}

var sensitivePatterns = regexp.MustCompile(`(?i)/var/run/secrets|/run/secrets|serviceaccount|\.kube/config|/etc/shadow|/etc/gshadow|/etc/sudoers|environ|id_rsa|id_ecdsa|id_ed25519|\.pem\b|\.key\b|\.p12\b|\.pfx\b|\.jks\b|keytab|\.vault-token|\.[a-z_]*history\b|\.aws/credentials|\.docker/config\.json|password|passwd|secret|token|credential`)

func sensitive(text string) error {
	if m := sensitivePatterns.FindString(text); m != "" {
		return fmt.Errorf("chemin ou motif sensible %q", m)
	}
	return nil
}

func readOnlyScript(script string, trusted []string, rules *Commands) error {
	if err := sensitive(script); err != nil {
		return err
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(script), "")
	if err != nil {
		return fmt.Errorf("script illisible : %v", err)
	}
	var first error
	fail := func(format string, a ...any) bool {
		if first == nil {
			first = fmt.Errorf(format, a...)
		}
		return false
	}
	syntax.Walk(f, func(n syntax.Node) bool {
		if first != nil {
			return false
		}
		switch x := n.(type) {
		case nil, *syntax.File, *syntax.Comment, *syntax.Word, *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted,
			*syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp,
			*syntax.BinaryArithm, *syntax.UnaryArithm, *syntax.ParenArithm, *syntax.Subshell, *syntax.Block,
			*syntax.IfClause, *syntax.WhileClause, *syntax.ForClause, *syntax.WordIter, *syntax.CStyleLoop,
			*syntax.CaseClause, *syntax.CaseItem, *syntax.TestClause, *syntax.BinaryTest, *syntax.UnaryTest,
			*syntax.ParenTest, *syntax.ArithmCmd, *syntax.LetClause, *syntax.TimeClause, *syntax.Assign,
			*syntax.ArrayExpr, *syntax.ArrayElem, *syntax.ExtGlob, *syntax.BraceExp:
			return true
		case *syntax.Stmt:
			if x.Background || x.Coprocess || x.Disown {
				return fail("exécution en arrière-plan")
			}
			return true
		case *syntax.BinaryCmd:
			return true
		case *syntax.ProcSubst:
			if x.Op != syntax.CmdIn {
				return fail("substitution de processus en écriture")
			}
			return true
		case *syntax.Redirect:
			if err := checkRedirect(x); err != nil {
				return fail("%v", err)
			}
			return true
		case *syntax.CallExpr:
			if len(x.Args) == 0 {
				return true
			}
			args := make([]arg, len(x.Args))
			for i, w := range x.Args {
				args[i] = wordArg(w)
			}
			if err := checkCall(args, trusted, rules); err != nil {
				return fail("%v", err)
			}
			return true
		}
		return fail("construction shell non admise (%T)", n)
	})
	return first
}

func checkRedirect(r *syntax.Redirect) error {
	target := ""
	if r.Word != nil {
		target = wordArg(r.Word).s
	}
	switch r.Op {
	case syntax.RdrIn, syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
		return nil
	case syntax.DplIn, syntax.DplOut:
		if dupTarget.MatchString(target) {
			return nil
		}
	case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll:
		if target == "/dev/null" {
			return nil
		}
	}
	return fmt.Errorf("redirection en écriture vers %q", target)
}

type arg struct {
	s   string
	lit bool
}

func wordArg(w *syntax.Word) arg {
	var b strings.Builder
	lit := true
	var walk func(parts []syntax.WordPart)
	walk = func(parts []syntax.WordPart) {
		for _, p := range parts {
			switch x := p.(type) {
			case *syntax.Lit:
				b.WriteString(x.Value)
			case *syntax.SglQuoted:
				b.WriteString(x.Value)
			case *syntax.DblQuoted:
				walk(x.Parts)
			default:
				lit = false
				b.WriteString("\x00")
			}
		}
	}
	walk(w.Parts)
	return arg{b.String(), lit}
}

var (
	anyArgs = set("ls", "cat", "head", "tail", "grep", "egrep", "fgrep", "zgrep", "zcat", "wc", "cut", "tr", "stat", "file",
		"readlink", "realpath", "basename", "dirname", "which", "whereis", "type", "uname", "id", "whoami", "groups",
		"ps", "df", "du", "free", "uptime", "echo", "printf", "true", "false", "test", "[", "pwd", "nproc", "arch",
		"getconf", "lsb_release", "sha1sum", "sha256sum", "sha512sum", "md5sum", "strings", "od", "tac", "nl", "comm",
		"diff", "cmp", "getent", "locale", "lscpu", "column", "expr", "seq", "dpkg-query", "ldconfig", "netstat",
		"lsof", "last", "lastlog", "who", "w", "getfacl", "lsattr", "pgrep", "ldd", "findmnt", "lsblk", "namei")
	dateLongValue   = set("date", "file", "reference")
	dateLongFlag    = set("utc", "universal", "rfc-email", "rfc-3339", "iso-8601", "debug", "help", "version", "resolution")
	nodeEval        = set("-p", "--print", "-e", "--eval")
	nodeVersionExpr = regexp.MustCompile(`^\s*(console\.log\(\s*)?process\.(version|versions(\.[A-Za-z0-9_]+|\[\s*["'][A-Za-z0-9_]+["']\s*\])?)(\s*\))?\s*;?\s*$`)
	versionArgs     = []string{"-v", "-V", "--version", "-version", "version", "-m", "-i", "-M", "-l"}
	versioned       = regexp.MustCompile(`^(php[0-9.]*|php-fpm[0-9.]*|php-cgi[0-9.]*|java|python[0-9.]*|node|nodejs|nginx|httpd|apache2|apachectl|apache2ctl|perl|ruby|go|mysql|mysqld|mariadb|postgres|psql|redis-server|curl|wget|git|openssl|dotnet|tomcat[0-9.]*|catalina\.sh|lighttpd|caddy|frankenphp|litespeed|lsphp[0-9.]*|rke2|k3s)$`)
	dupTarget       = regexp.MustCompile(`^(\d+|-)$`)
	sortOutput      = regexp.MustCompile(`^-[a-zA-Z]*o`)
	pipName         = regexp.MustCompile(`^pip[0-9.]*$`)
	rpmVerify       = regexp.MustCompile(`^-V[a-zA-Z]*$`)
	dnfCached       = set("list", "info", "repoquery", "check-update")
	dnfHistoryRead  = set("list", "info", "summary", "userinstalled")
	findActions     = set("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls")
	rpmWrite        = set("-i", "-U", "-F", "-e", "--install", "--upgrade", "--freshen", "--erase", "--import", "--rebuilddb", "--initdb", "--setperms", "--setugids", "--restore", "--delsign", "--addsign", "--reinstall")
	ssWrite         = set("-K", "--kill")
	journalWrite    = set("--rotate", "--flush", "--relinquish-var", "--smart-relinquish-var", "--sync", "--setup-keys", "--update-catalog")
	ipWrite         = set("add", "del", "delete", "change", "replace", "set", "flush", "append", "save", "restore", "exec", "up", "down", "attach", "detach")
	systemctlRead   = set("list-units", "list-unit-files", "list-timers", "list-sockets", "list-dependencies", "list-jobs", "status", "show", "cat", "is-active", "is-enabled", "is-failed", "is-system-running", "get-default")
	kubectlRead     = set("get", "describe", "logs", "top", "version", "api-resources", "api-versions", "explain", "events")
	kubectlGlobal   = set("-n", "--namespace", "--kubeconfig", "--context", "--cluster", "--user")
	kubectlOption   = regexp.MustCompile(`^(-A|--all-namespaces|--(namespace|kubeconfig|context|cluster|user|request-timeout)=.*)$`)
	kubectlRefused  = regexp.MustCompile(`^(-[a-zA-Z]*w[a-zA-Z]*|--watch(-only)?(=.*)?|--follow(=.*)?|--raw(=.*)?|-v(=.*)?|--v(=.*)?|--as(-group|-uid)?(=.*)?)$`)
	kubectlFollow   = regexp.MustCompile(`^-[a-zA-Z]*f[a-zA-Z]*$`)
	dpkgRead        = set("-l", "-L", "-s", "-S", "-p", "--list", "--listfiles", "--status", "--search", "--print-avail", "--print-architecture", "--version")
)

func set(items ...string) map[string]bool {
	m := map[string]bool{}
	for _, i := range items {
		m[i] = true
	}
	return m
}

func readOnlyCall(args []arg) error {
	name := args[0]
	if !name.lit || name.s == "" {
		return fmt.Errorf("programme non littéral")
	}
	if strings.Contains(name.s, "/") && !strings.HasPrefix(name.s, "/") {
		return fmt.Errorf("programme %q désigné par un chemin relatif", name.s)
	}
	prog := path.Base(name.s)
	rest := args[1:]
	literal := func() error {
		for _, a := range rest {
			if !a.lit {
				return fmt.Errorf("%s : argument non littéral", prog)
			}
		}
		return nil
	}
	operands := func() []string {
		var out []string
		for _, a := range rest {
			if !strings.HasPrefix(a.s, "-") {
				out = append(out, a.s)
			}
		}
		return out
	}
	first := ""
	if len(rest) > 0 {
		first = rest[0].s
	}
	switch {
	case anyArgs[prog]:
		if prog == "ldconfig" && (len(rest) != 1 || first != "-p") {
			return fmt.Errorf("ldconfig : seul -p est en lecture seule")
		}
		return nil
	case prog == "find":
		if err := literal(); err != nil {
			return err
		}
		for _, a := range rest {
			if findActions[a.s] {
				return fmt.Errorf("find %s écrit ou exécute", a.s)
			}
		}
		return nil
	case prog == "sort":
		if err := literal(); err != nil {
			return err
		}
		for _, a := range rest {
			if strings.HasPrefix(a.s, "--output") || sortOutput.MatchString(a.s) {
				return fmt.Errorf("sort -o écrit un fichier")
			}
		}
		return nil
	case prog == "uniq":
		if err := literal(); err != nil {
			return err
		}
		if len(operands()) > 1 {
			return fmt.Errorf("uniq avec un fichier de sortie")
		}
		return nil
	case prog == "date":
		if err := literal(); err != nil {
			return err
		}
		return readOnlyDate(rest)
	case prog == "hostname":
		if err := literal(); err != nil {
			return err
		}
		if len(operands()) > 0 {
			return fmt.Errorf("hostname avec argument modifie le nom")
		}
		return nil
	case prog == "ss":
		if err := literal(); err != nil {
			return err
		}
		for _, a := range rest {
			if ssWrite[a.s] {
				return fmt.Errorf("ss %s ferme des connexions", a.s)
			}
		}
		return nil
	case prog == "crontab":
		if len(rest) == 1 && first == "-l" || len(rest) == 3 && first == "-u" && rest[2].s == "-l" || len(rest) == 3 && first == "-l" && rest[1].s == "-u" {
			return literal()
		}
		return fmt.Errorf("crontab : seul -l est en lecture seule")
	case prog == "systemctl":
		if err := literal(); err != nil {
			return err
		}
		for _, a := range rest {
			if strings.HasPrefix(a.s, "-") {
				continue
			}
			if systemctlRead[a.s] {
				return nil
			}
			return fmt.Errorf("systemctl %s modifie l'état", a.s)
		}
		return nil
	case prog == "journalctl":
		if err := literal(); err != nil {
			return err
		}
		for _, a := range rest {
			if journalWrite[a.s] || strings.HasPrefix(a.s, "--vacuum") {
				return fmt.Errorf("journalctl %s écrit", a.s)
			}
		}
		return nil
	case prog == "ip":
		if err := literal(); err != nil {
			return err
		}
		for _, a := range rest {
			if ipWrite[a.s] {
				return fmt.Errorf("ip %s modifie la configuration réseau", a.s)
			}
		}
		return nil
	case prog == "kubectl" || prog == "oc":
		if err := literal(); err != nil {
			return err
		}
		return readOnlyKubectl(prog, rest)
	case prog == "command":
		if len(rest) >= 2 && (first == "-v" || first == "-V") {
			return nil
		}
		return fmt.Errorf("command : seuls -v et -V sont admis")
	case prog == "dpkg":
		if len(rest) > 0 && dpkgRead[first] {
			return literal()
		}
		return fmt.Errorf("dpkg %s n'est pas une interrogation", first)
	case prog == "rpm":
		if err := literal(); err != nil {
			return err
		}
		for _, a := range rest {
			if rpmWrite[a.s] {
				return fmt.Errorf("rpm %s écrit", a.s)
			}
		}
		if strings.HasPrefix(first, "-q") || first == "--query" || rpmVerify.MatchString(first) || first == "--verify" || first == "--version" {
			return nil
		}
		return fmt.Errorf("rpm %s n'est pas une interrogation", first)
	case prog == "dnf" || prog == "yum" || prog == "dnf5":
		if err := literal(); err != nil {
			return err
		}
		return readOnlyDnf(prog, rest)
	case prog == "apk":
		if ops := operands(); len(ops) > 0 && set("info", "list", "version", "search", "policy")[ops[0]] || first == "--version" {
			return literal()
		}
		return fmt.Errorf("apk : seules les interrogations sont admises")
	case prog == "snap":
		if ops := operands(); len(ops) > 0 && set("list", "info", "version", "connections", "services", "known")[ops[0]] || first == "--version" {
			return literal()
		}
		return fmt.Errorf("snap : seules les interrogations sont admises")
	case prog == "flatpak":
		if ops := operands(); len(ops) > 0 && set("list", "info", "ps")[ops[0]] || first == "--version" {
			return literal()
		}
		return fmt.Errorf("flatpak : seules les interrogations sont admises")
	case pipName.MatchString(prog):
		if set("list", "show", "freeze", "--version", "-V")[first] {
			return literal()
		}
		return fmt.Errorf("%s %s n'est pas une interrogation", prog, first)
	case prog == "npm":
		if set("ls", "list", "view", "--version", "-v")[first] {
			return literal()
		}
		return fmt.Errorf("npm %s n'est pas une interrogation", first)
	case prog == "gem":
		if set("list", "--version")[first] {
			return literal()
		}
		return fmt.Errorf("gem %s n'est pas une interrogation", first)
	case (prog == "node" || prog == "nodejs") && len(rest) == 2 && nodeEval[first]:
		if err := literal(); err != nil {
			return err
		}
		if !nodeVersionExpr.MatchString(rest[1].s) || first != "-p" && first != "--print" && !strings.HasPrefix(strings.TrimSpace(rest[1].s), "console.log(") {
			return fmt.Errorf("%s %s : seule la lecture de process.version ou process.versions est admise", prog, first)
		}
		return nil
	case versioned.MatchString(prog):
		if err := literal(); err != nil {
			return err
		}
		if len(rest) == 0 {
			return fmt.Errorf("%s sans option de version", prog)
		}
		for _, a := range rest {
			if !slices.Contains(versionArgs, a.s) {
				return fmt.Errorf("%s %s : seules les options de version sont admises", prog, a.s)
			}
		}
		return nil
	case len(rest) == 1 && rest[0].lit && first == "--version":
		return nil
	}
	return fmt.Errorf("programme %s non reconnu en lecture seule", prog)
}

func readOnlyDnf(prog string, rest []arg) error {
	var ops []string
	cached := false
	for _, a := range rest {
		switch {
		case a.s == "-C" || a.s == "--cacheonly":
			cached = true
		case a.s == "-q" || a.s == "--quiet" || a.s == "--reverse":
		case strings.HasPrefix(a.s, "--disablerepo=") || strings.HasPrefix(a.s, "--enablerepo="):
		case strings.HasPrefix(a.s, "-"):
			return fmt.Errorf("%s %s : option non admise en lecture seule", prog, a.s)
		default:
			ops = append(ops, a.s)
		}
	}
	if len(ops) == 0 {
		return fmt.Errorf("%s sans sous-commande", prog)
	}
	switch {
	case ops[0] == "repolist":
		return nil
	case ops[0] == "history" && (len(ops) == 1 || dnfHistoryRead[ops[1]]):
		return nil
	case dnfCached[ops[0]] && cached:
		return nil
	case dnfCached[ops[0]]:
		return fmt.Errorf("%s %s peut rafraîchir le cache sans -C", prog, ops[0])
	}
	return fmt.Errorf("%s %s n'est pas une interrogation", prog, ops[0])
}

func readOnlyDate(rest []arg) error {
	for i := 0; i < len(rest); i++ {
		a := rest[i].s
		switch {
		case strings.HasPrefix(a, "+"):
		case strings.HasPrefix(a, "--") && len(a) > 2:
			name, _, attached := strings.Cut(a[2:], "=")
			switch {
			case dateLongValue[name]:
				if !attached {
					i++
				}
			case !dateLongFlag[name]:
				return fmt.Errorf("date %s modifie l'heure ou n'est pas reconnue", a)
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			next, err := dateShort(a)
			if err != nil {
				return err
			}
			if next {
				i++
			}
		default:
			return fmt.Errorf("date %s modifie l'heure", a)
		}
	}
	return nil
}

func dateShort(a string) (bool, error) {
	for i, c := range a[1:] {
		switch c {
		case 'u', 'R':
		case 'I':
			return false, nil
		case 'd', 'f', 'r':
			return i == len(a)-2, nil
		default:
			return false, fmt.Errorf("date %s modifie l'heure ou n'est pas reconnue", a)
		}
	}
	return false, nil
}

func readOnlyKubectl(prog string, rest []arg) error {
	i := 0
	for i < len(rest) && strings.HasPrefix(rest[i].s, "-") {
		switch {
		case kubectlGlobal[rest[i].s]:
			i += 2
		case kubectlOption.MatchString(rest[i].s):
			i++
		default:
			return fmt.Errorf("%s %s : option globale non admise", prog, rest[i].s)
		}
	}
	if i >= len(rest) {
		return fmt.Errorf("%s sans sous-commande", prog)
	}
	verb := rest[i].s
	after := rest[i+1:]
	switch {
	case verb == "cluster-info" && len(after) == 0:
		return nil
	case verb == "auth" && len(after) > 0 && after[0].s == "can-i":
	case !kubectlRead[verb]:
		return fmt.Errorf("%s %s n'est pas une consultation", prog, verb)
	}
	for _, a := range after {
		if kubectlRefused.MatchString(a.s) || verb == "logs" && kubectlFollow.MatchString(a.s) {
			return fmt.Errorf("%s %s %s : suivi sans fin ou accès brut", prog, verb, a.s)
		}
	}
	return nil
}

func trustedCall(args []arg, trusted []string) bool {
	words := make([]string, len(args))
	for i, a := range args {
		if !a.lit {
			return false
		}
		words[i] = a.s
	}
	for _, c := range trusted {
		if w, ok := literalWords(c); ok && slices.Equal(w, words) {
			return true
		}
	}
	return false
}

func literalWords(line string) ([]string, bool) {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(line), "")
	if err != nil || len(f.Stmts) != 1 {
		return nil, false
	}
	st := f.Stmts[0]
	call, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(st.Redirs) > 0 || len(call.Assigns) > 0 || st.Negated || st.Background {
		return nil, false
	}
	out := make([]string, len(call.Args))
	for i, w := range call.Args {
		a := wordArg(w)
		if !a.lit {
			return nil, false
		}
		out[i] = a.s
	}
	return out, true
}
