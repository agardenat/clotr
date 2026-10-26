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
	if err := CheckArgv(argv); err != nil {
		return err
	}
	if script, ok := ShellScript(argv); ok {
		return readOnlyScript(script)
	}
	args := make([]arg, len(argv))
	for i, a := range argv {
		args[i] = arg{a, true}
	}
	if err := sensitive(strings.Join(argv, " ")); err != nil {
		return err
	}
	return readOnlyCall(args)
}

var sensitivePatterns = regexp.MustCompile(`(?i)/var/run/secrets|/run/secrets|serviceaccount|\.kube/config|/etc/shadow|/etc/gshadow|/etc/sudoers|environ|id_rsa|id_ecdsa|id_ed25519|\.pem\b|\.key\b|\.p12\b|\.pfx\b|\.jks\b|keytab|\.vault-token|\.aws/credentials|\.docker/config\.json|password|passwd|secret|token|credential`)

func sensitive(text string) error {
	if m := sensitivePatterns.FindString(text); m != "" {
		return fmt.Errorf("chemin ou motif sensible %q", m)
	}
	return nil
}

func readOnlyScript(script string) error {
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
			if err := readOnlyCall(args); err != nil {
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
		"lsof", "last", "lastlog", "who", "w", "getfacl", "lsattr", "pgrep", "ldd")
	versionArgs   = []string{"-v", "-V", "--version", "-version", "version", "-m", "-i", "-M", "-l"}
	versioned     = regexp.MustCompile(`^(php[0-9.]*|php-fpm[0-9.]*|php-cgi[0-9.]*|java|python[0-9.]*|node|nodejs|nginx|httpd|apache2|apachectl|apache2ctl|perl|ruby|go|mysql|mysqld|mariadb|postgres|psql|redis-server|curl|wget|git|openssl|dotnet|tomcat[0-9.]*|catalina\.sh|lighttpd|caddy|frankenphp|litespeed|lsphp[0-9.]*)$`)
	dupTarget     = regexp.MustCompile(`^(\d+|-)$`)
	sortOutput    = regexp.MustCompile(`^-[a-zA-Z]*o`)
	pipName       = regexp.MustCompile(`^pip[0-9.]*$`)
	findActions   = set("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls")
	rpmWrite      = set("-i", "-U", "-F", "-e", "--install", "--upgrade", "--freshen", "--erase", "--import", "--rebuilddb", "--initdb", "--setperms", "--setugids", "--restore", "--delsign", "--addsign", "--reinstall")
	ssWrite       = set("-K", "--kill")
	journalWrite  = set("--rotate", "--flush", "--relinquish-var", "--smart-relinquish-var", "--sync", "--setup-keys", "--update-catalog")
	ipWrite       = set("add", "del", "delete", "change", "replace", "set", "flush", "append", "save", "restore", "exec", "up", "down", "attach", "detach")
	systemctlRead = set("list-units", "list-unit-files", "list-timers", "list-sockets", "list-dependencies", "list-jobs", "status", "show", "cat", "is-active", "is-enabled", "is-failed", "is-system-running", "get-default")
	dpkgRead      = set("-l", "-L", "-s", "-S", "-p", "--list", "--listfiles", "--status", "--search", "--print-avail", "--print-architecture", "--version")
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
		for _, a := range rest {
			if a.s == "-s" || strings.HasPrefix(a.s, "--set") || (!strings.HasPrefix(a.s, "-") && !strings.HasPrefix(a.s, "+")) {
				return fmt.Errorf("date %s modifie l'heure", a.s)
			}
		}
		return nil
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
		if strings.HasPrefix(first, "-q") || first == "--query" || first == "-V" || first == "--verify" || first == "--version" {
			return nil
		}
		return fmt.Errorf("rpm %s n'est pas une interrogation", first)
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
