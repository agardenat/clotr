package access

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

var sensitiveSamples = []string{"/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/sudoers", "/etc/sudoers.d/admins", "/etc/krb5.keytab", "/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ed25519_key", "/root/.ssh/id_rsa", "/root/.ssh/id_ed25519", "/root/.bash_history", "/root/.kube/config", "/home/user/.ssh/id_rsa", "/home/user/.ssh/id_ed25519", "/home/user/.bash_history", "/home/user/.kube/config", "/proc/1/environ", "/proc/self/environ", "/var/run/secrets/kubernetes.io/serviceaccount/token", "/run/secrets/kubernetes.io/serviceaccount/token", "/etc/ssl/private/server.key", "/etc/pki/tls/private/server.key", "/etc/rancher/rke2/rke2.yaml", "/etc/kubernetes/admin.conf"}

var homeSamples = []string{".bash_history", ".zsh_history", ".ssh/id_rsa", ".ssh/id_ecdsa", ".ssh/id_ed25519", ".kube/config", ".vault-token", ".aws/credentials", ".docker/config.json"}

func sensitiveGlob(a string) error {
	if !strings.ContainsAny(a, "*?[") {
		return nil
	}
	samples := sensitiveSamples
	if !strings.HasPrefix(a, "/") {
		samples = homeSamples
	}
	for _, s := range samples {
		if globMatch(a, s) {
			return fmt.Errorf("motif %q pouvant désigner %s", a, s)
		}
	}
	return nil
}

func globMatch(pattern, name string) bool {
	ps, ns := strings.Split(pattern, "/"), strings.Split(name, "/")
	if len(ps) != len(ns) {
		return false
	}
	for i := range ps {
		if strings.HasPrefix(ns[i], ".") && !strings.HasPrefix(ps[i], ".") {
			return false
		}
		if ok, _ := path.Match(ps[i], ns[i]); !ok {
			return false
		}
	}
	return true
}

var (
	exemptAll       = set("ls", "stat", "namei", "getfacl", "lsattr", "readlink", "realpath", "dirname", "basename", "test", "[", "which", "whereis", "type", "command", "file", "du", "echo", "printf")
	grepPrograms    = set("grep", "egrep", "fgrep", "zgrep")
	awkPrograms     = set("awk", "gawk", "mawk", "nawk")
	kubectlPatterns = set("-o", "--output", "-l", "--selector", "--field-selector", "--sort-by", "--template")
)

const grepValued = "efmABCdD"

func exemptions(args []arg) []bool {
	ex := make([]bool, len(args))
	n := sudoLen(args)
	if n >= len(args) || !args[n].lit {
		return ex
	}
	prog := path.Base(args[n].s)
	rest := args[n+1:]
	mark := func(i int) {
		if i >= 0 && i < len(rest) && rest[i].lit {
			ex[n+1+i] = true
		}
	}
	switch {
	case exemptAll[prog] || prog == "find" && !slices.ContainsFunc(rest, func(a arg) bool { return findActions[a.s] }):
		for i := range rest {
			mark(i)
		}
	case grepPrograms[prog]:
		grepPatterns(rest, mark)
	case prog == "sed" || awkPrograms[prog]:
		explicit := false
		for i := 0; i < len(rest); i++ {
			s := rest[i].s
			switch {
			case s == "-e" || s == "--expression":
				explicit = true
				mark(i + 1)
				i++
			case strings.HasPrefix(s, "--expression="):
				explicit = true
				mark(i)
			case s == "-F" || s == "-v" || s == "-l":
				i++
			case strings.HasPrefix(s, "-"):
			default:
				if !explicit {
					mark(i)
				}
				return ex
			}
		}
	case prog == "kubectl" || prog == "oc":
		for i := 0; i < len(rest); i++ {
			name, _, attached := strings.Cut(rest[i].s, "=")
			if !kubectlPatterns[name] {
				continue
			}
			if attached {
				mark(i)
			} else {
				mark(i + 1)
				i++
			}
		}
	case prog == "journalctl":
		for i := 0; i < len(rest); i++ {
			switch {
			case rest[i].s == "-g" || rest[i].s == "--grep":
				mark(i + 1)
				i++
			case strings.HasPrefix(rest[i].s, "--grep="):
				mark(i)
			}
		}
	}
	return ex
}

func grepPatterns(rest []arg, mark func(int)) {
	explicit := false
	for i := 0; i < len(rest); i++ {
		s := rest[i].s
		switch {
		case s == "--":
			if !explicit {
				mark(i + 1)
			}
			return
		case s == "--regexp":
			explicit = true
			mark(i + 1)
			i++
		case strings.HasPrefix(s, "--regexp="):
			explicit = true
			mark(i)
		case s == "--file" || strings.HasPrefix(s, "--file="):
			explicit = true
			if s == "--file" {
				i++
			}
		case strings.HasPrefix(s, "--"):
		case len(s) > 1 && s[0] == '-':
			for j := 1; j < len(s); j++ {
				c := s[j]
				if strings.IndexByte(grepValued, c) < 0 {
					continue
				}
				last := j == len(s)-1
				switch c {
				case 'e':
					explicit = true
					if last {
						mark(i + 1)
					} else {
						mark(i)
					}
				case 'f':
					explicit = true
				}
				if last {
					i++
				}
				break
			}
		default:
			if !explicit {
				mark(i)
				explicit = true
			}
		}
	}
}

func sensitiveArgs(args []arg) error {
	n := sudoLen(args)
	if n < len(args) {
		words := make([]string, 0, len(args)-n)
		for _, a := range args[n:] {
			words = append(words, a.s)
		}
		if _, ok := ShellScript(words); ok {
			return nil
		}
	}
	ex := exemptions(args)
	var kept []string
	for i, a := range args {
		if ex[i] {
			continue
		}
		kept = append(kept, a.s)
		if a.lit {
			if err := sensitiveGlob(a.s); err != nil {
				return err
			}
		}
	}
	return sensitive(strings.Join(kept, " "))
}

func sensitiveScript(f *syntax.File, script string) error {
	blank := []byte(script)
	clear := func(w *syntax.Word) {
		for i := int(w.Pos().Offset()); i < int(w.End().Offset()) && i < len(blank); i++ {
			blank[i] = ' '
		}
	}
	var first error
	syntax.Walk(f, func(n syntax.Node) bool {
		x, ok := n.(*syntax.CallExpr)
		if first != nil || !ok {
			return first == nil
		}
		args := make([]arg, len(x.Args))
		for i, w := range x.Args {
			args[i] = wordArg(w)
		}
		if k := sudoLen(args); k < len(args) {
			words := make([]string, 0, len(args)-k)
			literal := true
			for _, a := range args[k:] {
				words = append(words, a.s)
				literal = literal && a.lit
			}
			if _, ok := ShellScript(words); ok && literal {
				clear(x.Args[len(x.Args)-1])
				return true
			}
		}
		for i, exempt := range exemptions(args) {
			switch {
			case exempt:
				clear(x.Args[i])
			case args[i].lit:
				if err := sensitiveGlob(args[i].s); err != nil {
					first = err
					return false
				}
			}
		}
		return true
	})
	if first != nil {
		return first
	}
	return sensitive(string(blank))
}

var (
	prefixVars    = set("LANG", "LANGUAGE", "TZ", "COLUMNS", "LINES", "TERM", "NO_COLOR", "SYSTEMD_COLORS", "SYSTEMD_LESS")
	dangerousVars = set("PATH", "IFS", "BASH_ENV", "ENV", "EDITOR", "VISUAL", "PROMPT_COMMAND", "PS4", "SHELLOPTS", "BASHOPTS", "HOME", "KUBECONFIG", "NODE_OPTIONS", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "GCONV_PATH", "CDPATH", "GLOBIGNORE", "BASH_XTRACEFD", "TMPDIR")
)

func prefixVar(name string) bool {
	return prefixVars[name] || strings.HasPrefix(name, "LC_")
}

func dangerousVar(name string) bool {
	if dangerousVars[name] {
		return true
	}
	for _, p := range []string{"LD_", "DYLD_", "PYTHON", "PERL5", "PERL_", "RUBY", "GIT_", "BASH_FUNC_"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return strings.HasSuffix(name, "PAGER")
}

func varName(a *syntax.Assign) string {
	if a.Name == nil {
		return "?"
	}
	return a.Name.Value
}

func versionOnly(rest []arg) bool {
	if len(rest) == 0 {
		return false
	}
	for _, a := range rest {
		if !a.lit || !slices.Contains(versionArgs, a.s) {
			return false
		}
	}
	return true
}
