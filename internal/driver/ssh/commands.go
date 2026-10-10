package ssh

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
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
			return nil, fmt.Errorf("ssh_paths.allow: %q doit être absolu", g)
		}
		out.allow = append(out.allow, globRegexp(g))
	}
	for _, g := range r.Deny {
		out.deny = append(out.deny, globRegexp(g))
	}
	if len(out.allow) == 0 {
		return nil, fmt.Errorf("ssh_paths.allow: au moins un chemin requis")
	}
	return out, nil
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

func (b Builder) Disk(dir string, depth, limit int) string {
	p, q := b.prefix(), Quote(dir)
	return fmt.Sprintf("%sdf -hP -- %s; echo '--- du'; %sdu -xh --max-depth=%d -- %s 2>/dev/null | sort -rh | head -n %d; echo '--- files'; %sfind %s -xdev -type f 2>/dev/null | wc -l", p, q, p, depth, q, limit, p, q)
}

func (b Builder) StatTail(file string, maxBytes int) string {
	return fmt.Sprintf("%sstat -c '%%s %%Y' -- %s && %stail -c %d -- %s", b.prefix(), Quote(file), b.prefix(), maxBytes, Quote(file))
}

func (b Builder) Read(file string, from, to, maxBytes int) string {
	if from > 0 {
		if to < from {
			to = from + 199
		}
		return fmt.Sprintf("%ssed -n %s -- %s | head -c %d", b.prefix(), Quote(strconv.Itoa(from)+","+strconv.Itoa(to)+"p"), Quote(file), maxBytes)
	}
	return fmt.Sprintf("%shead -c %d -- %s", b.prefix(), maxBytes, Quote(file))
}

func (b Builder) Tail(file string, lines int) string {
	return fmt.Sprintf("%stail -n %d -- %s", b.prefix(), lines, Quote(file))
}

func (b Builder) TailFiltered(file, pattern string, lines int) string {
	return fmt.Sprintf("%sgrep -E -I -e %s -- %s | tail -n %d", b.prefix(), Quote(pattern), Quote(file), lines)
}

func (b Builder) Grep(p, pattern string, ignoreCase, recursive bool, maxCount int, excludes []string, maxBytes int) string {
	var opts []string
	opts = append(opts, "-n", "-E", "-I", "-m", strconv.Itoa(maxCount))
	if ignoreCase {
		opts = append(opts, "-i")
	}
	if recursive {
		opts = append(opts, "-r")
		for _, e := range excludes {
			opts = append(opts, "--exclude="+Quote(e))
		}
	}
	return fmt.Sprintf("%sgrep %s -e %s -- %s | head -c %d", b.prefix(), strings.Join(opts, " "), Quote(pattern), Quote(p), maxBytes)
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
