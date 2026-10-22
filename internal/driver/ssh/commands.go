package ssh

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/agardenat/clotr/internal/i18n"
)

type PathRules struct {
	Allow []string `yaml:"allow" json:"allow"`
	Deny  []string `yaml:"deny" json:"deny"`
}

type Rules struct {
	allow []*regexp.Regexp
	deny  []*regexp.Regexp
	src   PathRules
}

func CompileRules(r PathRules) (*Rules, error) {
	out := &Rules{src: r}
	for _, g := range r.Allow {
		if !strings.HasPrefix(g, "/") {
			return nil, i18n.E("ssh.paths_absolute", g)
		}
		out.allow = append(out.allow, globRegexp(g))
	}
	for _, g := range r.Deny {
		out.deny = append(out.deny, globRegexp(g))
	}
	if len(out.allow) == 0 {
		return nil, i18n.E("ssh.paths_required")
	}
	return out, nil
}

func (r *Rules) Source() PathRules {
	return r.src
}

func globRegexp(g string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(g); i++ {
		c := g[i]
		switch {
		case c == '*' && i+1 < len(g) && g[i+1] == '*':
			i++
			if i+1 < len(g) && g[i+1] == '/' {
				i++
				b.WriteString("(.*/)?")
			} else {
				b.WriteString(".*")
			}
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

var unsafeChars = regexp.MustCompile("[\x00-\x1f\x7f]")

func (r *Rules) Check(p string) (string, error) {
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("chemin %q: absolu requis", p)
	}
	if unsafeChars.MatchString(p) || strings.Contains(p, "..") {
		return "", fmt.Errorf("chemin %q refusé", p)
	}
	clean := path.Clean(p)
	for _, d := range r.deny {
		if d.MatchString(clean) {
			return "", fmt.Errorf("chemin %q refusé par ssh_paths.deny", clean)
		}
	}
	for _, a := range r.allow {
		if a.MatchString(clean) {
			return clean, nil
		}
	}
	return "", fmt.Errorf("chemin %q hors de ssh_paths.allow (%s)", clean, strings.Join(r.src.Allow, ", "))
}

func (r *Rules) ExcludeGlobs() []string {
	var out []string
	for _, d := range r.src.Deny {
		base := d
		if i := strings.LastIndex(d, "/"); i >= 0 {
			base = d[i+1:]
		}
		if base != "" && !strings.Contains(base, "**") {
			out = append(out, base)
		}
	}
	return out
}

func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

type Builder struct {
	Sudo bool
}

func (b Builder) prefix() string {
	if b.Sudo {
		return "sudo -n "
	}
	return ""
}

func SudoWithPassword(cmd string) string {
	return "sudo -S -p '' -- sh -c " + Quote("exec </dev/null; "+cmd)
}

var sudoPasswordMessages = []string{"sudo: a password is required", "sudo: a terminal is required to read the password"}

func SudoNeedsPassword(res Result) bool {
	for _, m := range sudoPasswordMessages {
		if strings.Contains(res.Stderr, m) || strings.HasPrefix(res.Stdout, m) {
			return true
		}
	}
	return false
}

func SudoPasswordRejected(stderr string) bool {
	return strings.Contains(stderr, "incorrect password attempt") || strings.Contains(stderr, "Sorry, try again")
}

func (b Builder) List(dir string, depth, limit int, sortBy string) string {
	sorter := ""
	switch sortBy {
	case "size":
		sorter = " | sort -k2,2nr"
	case "mtime":
		sorter = " | sort -k3,4r"
	}
	return fmt.Sprintf("%sfind %s -maxdepth %d -printf '%%y %%s %%TY-%%Tm-%%Td %%TH:%%TM %%p\\n' 2>&1%s | head -n %d", b.prefix(), Quote(dir), depth, sorter, limit)
}

func Exec(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = Quote(a)
	}
	return "exec " + strings.Join(q, " ") + " </dev/null"
}

func (b Builder) Resolve(name string, resolvConf bool) string {
	cmd := "getent ahosts " + Quote(name) + `; echo "--- exit $?"`
	if resolvConf {
		cmd += "; echo '--- resolv.conf'; grep -E '^(nameserver|search|domain)' /etc/resolv.conf"
	}
	return cmd
}

func (b Builder) Disk(dir string, depth, limit int) string {
	p, q := b.prefix(), Quote(dir)
	return fmt.Sprintf("%sdf -hP -- %s; echo '--- du'; %sdu -xh --max-depth=%d -- %s 2>/dev/null | sort -rh | head -n %d; echo '--- files'; %sfind %s -xdev -type f 2>/dev/null | wc -l", p, q, p, depth, q, limit, p, q)
}

func Compressed(file string) bool {
	return strings.HasSuffix(file, ".gz")
}

func (b Builder) source(file string) (string, bool) {
	if !Compressed(file) {
		return "", false
	}
	p, q := b.prefix(), Quote(file)
	return fmt.Sprintf("%sgzip -t -- %s && %sgzip -cd -- %s | ", p, q, p, q), true
}

func (b Builder) StatTail(file string, maxBytes int) string {
	if src, ok := b.source(file); ok {
		return fmt.Sprintf("%swc -c | tr -d ' \\n' && printf ' ' && %sstat -c '%%Y' -- %s && %sgzip -cd -- %s | tail -c %d", src, b.prefix(), Quote(file), b.prefix(), Quote(file), maxBytes)
	}
	return fmt.Sprintf("%sstat -c '%%s %%Y' -- %s && %stail -c %d -- %s", b.prefix(), Quote(file), b.prefix(), maxBytes, Quote(file))
}

func (b Builder) Read(file string, from, to, maxBytes int) string {
	src, gz := b.source(file)
	if from > 0 {
		if to < from {
			to = from + 199
		}
		lines := Quote(strconv.Itoa(from) + "," + strconv.Itoa(to) + "p")
		if gz {
			return fmt.Sprintf("%ssed -n %s | head -c %d", src, lines, maxBytes)
		}
		return fmt.Sprintf("%ssed -n %s -- %s | head -c %d", b.prefix(), lines, Quote(file), maxBytes)
	}
	if gz {
		return fmt.Sprintf("%shead -c %d", src, maxBytes)
	}
	return fmt.Sprintf("%shead -c %d -- %s", b.prefix(), maxBytes, Quote(file))
}

func (b Builder) Tail(file string, lines int) string {
	if src, ok := b.source(file); ok {
		return fmt.Sprintf("%stail -n %d", src, lines)
	}
	return fmt.Sprintf("%stail -n %d -- %s", b.prefix(), lines, Quote(file))
}

func (b Builder) TailFiltered(file, pattern string, lines int) string {
	if src, ok := b.source(file); ok {
		return fmt.Sprintf("%sgrep -E -I -e %s | tail -n %d", src, Quote(pattern), lines)
	}
	return fmt.Sprintf("%sgrep -E -I -e %s -- %s | tail -n %d", b.prefix(), Quote(pattern), Quote(file), lines)
}

func (b Builder) Grep(p, pattern string, ignoreCase, recursive bool, maxCount int, excludes []string, maxBytes int) string {
	var opts []string
	opts = append(opts, "-n", "-E", "-I", "-m", strconv.Itoa(maxCount))
	if ignoreCase {
		opts = append(opts, "-i")
	}
	if !recursive {
		if src, ok := b.source(p); ok {
			return fmt.Sprintf("%sgrep %s -e %s | head -c %d", src, strings.Join(opts, " "), Quote(pattern), maxBytes)
		}
	}
	if recursive {
		opts = append(opts, "-r")
		for _, e := range excludes {
			opts = append(opts, "--exclude="+Quote(e))
		}
	}
	return fmt.Sprintf("%sgrep %s -e %s -- %s | head -c %d", b.prefix(), strings.Join(opts, " "), Quote(pattern), Quote(p), maxBytes)
}

func (b Builder) GrepCount(p, pattern string, ignoreCase, recursive bool, excludes []string, maxBytes int) string {
	opts := []string{"-c", "-E", "-I"}
	if ignoreCase {
		opts = append(opts, "-i")
	}
	if !recursive {
		if src, ok := b.source(p); ok {
			return fmt.Sprintf("%sgrep %s -e %s | head -c %d", src, strings.Join(opts, " "), Quote(pattern), maxBytes)
		}
	}
	nonZero := ""
	if recursive {
		opts = append(opts, "-r")
		for _, e := range excludes {
			opts = append(opts, "--exclude="+Quote(e))
		}
		nonZero = " | grep -v ':0$'"
	}
	return fmt.Sprintf("%sgrep %s -e %s -- %s%s | head -c %d", b.prefix(), strings.Join(opts, " "), Quote(pattern), Quote(p), nonZero, maxBytes)
}

func (b Builder) Recent(dirs []string, minutes, limit int) string {
	q := make([]string, len(dirs))
	for i, d := range dirs {
		q[i] = Quote(d)
	}
	age := ""
	if minutes > 0 {
		age = fmt.Sprintf(" -mmin -%d", minutes)
	}
	return fmt.Sprintf("%sfind %s -type f \\( -name '*.log' -o -name '*.out' -o -name '*.log.[0-9]*' \\)%s -printf '%%T@ %%s %%p\\n' 2>/dev/null | sort -rn | head -n %d", b.prefix(), strings.Join(q, " "), age, limit)
}

var (
	kvSecret  = regexp.MustCompile(`(?i)((?:password|passwd|pwd|secret|token|credential|private[._-]?key|access[._-]?key)[\w.\-]*\s*["']?\s*[=:]\s*["']?)([^\s"'<>,;]+)`)
	xmlSecret = regexp.MustCompile(`(?is)(<name>[^<]*(?:password|passwd|secret|token|credential)[^<]*</name>\s*<value>)([^<]*)(</value>)`)
)

func Redact(s string) string {
	s = xmlSecret.ReplaceAllString(s, "${1}[REDACTED]${3}")
	return kvSecret.ReplaceAllString(s, "${1}[REDACTED]")
}
