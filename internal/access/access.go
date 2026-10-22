package access

import (
	"regexp"
	"slices"
	"strings"

	"github.com/agardenat/clotr/internal/i18n"
)

type Level int

const (
	Read Level = iota
	Exec
	Create
)

var names = []string{"read", "exec", "create"}

func Names() []string {
	return slices.Clone(names)
}

func Parse(s string) (Level, error) {
	if s == "" {
		return Read, nil
	}
	if i := slices.Index(names, s); i >= 0 {
		return Level(i), nil
	}
	return Read, i18n.E("access.unknown", s, strings.Join(names, "|"))
}

func (l Level) String() string {
	if l < Read || int(l) >= len(names) {
		return "read"
	}
	return names[l]
}

func (l Level) Allows(required Level) bool {
	return l >= required
}

type Rules struct {
	Allow []string `yaml:"allow" json:"allow"`
	Deny  []string `yaml:"deny" json:"deny"`
}

type Decision int

const (
	Ask Decision = iota
	Allowed
	Denied
)

type pattern struct {
	src  string
	args []*regexp.Regexp
	rest bool
}

type Commands struct {
	allow []pattern
	deny  []pattern
	src   Rules
}

var unsafeArg = regexp.MustCompile("[\x00-\x1f\x7f]")

func CompileCommands(r Rules) (*Commands, error) {
	c := &Commands{src: r}
	for field, list := range map[string][]string{"allow": r.Allow, "deny": r.Deny} {
		for i, s := range list {
			p, err := compilePattern(s)
			if err != nil {
				return nil, i18n.E("access.pattern", field, i, s, err)
			}
			if field == "allow" {
				c.allow = append(c.allow, p)
			} else {
				c.deny = append(c.deny, p)
			}
		}
	}
	return c, nil
}

func compilePattern(s string) (pattern, error) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return pattern{}, i18n.E("access.pattern_empty")
	}
	if unsafeArg.MatchString(s) {
		return pattern{}, i18n.E("access.pattern_chars")
	}
	p := pattern{src: strings.Join(fields, " ")}
	for i, f := range fields {
		if f == "**" {
			if i != len(fields)-1 || i == 0 {
				return pattern{}, i18n.E("access.pattern_rest")
			}
			p.rest = true
			break
		}
		p.args = append(p.args, globArg(f))
	}
	return p, nil
}

func globArg(g string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for _, c := range g {
		switch c {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

func (p pattern) match(argv []string) bool {
	if len(argv) < len(p.args) || (!p.rest && len(argv) != len(p.args)) {
		return false
	}
	for i, re := range p.args {
		if !re.MatchString(argv[i]) {
			return false
		}
	}
	return true
}

func (c *Commands) Source() Rules {
	if c == nil {
		return Rules{}
	}
	return c.src
}

func (c *Commands) Extend(extra Rules) (*Commands, error) {
	src := c.Source()
	return CompileCommands(Rules{Allow: append(slices.Clone(src.Allow), extra.Allow...), Deny: append(slices.Clone(src.Deny), extra.Deny...)})
}

func CheckArgv(argv []string) error {
	if len(argv) == 0 || strings.TrimSpace(argv[0]) == "" {
		return i18n.E("access.argv_empty")
	}
	for _, a := range argv {
		if unsafeArg.MatchString(a) {
			return i18n.E("access.argv_chars", a)
		}
	}
	return nil
}

func (c *Commands) Check(argv []string) Decision {
	if c == nil {
		return Ask
	}
	for _, p := range c.deny {
		if p.match(argv) {
			return Denied
		}
	}
	for _, p := range c.allow {
		if p.match(argv) {
			return Allowed
		}
	}
	return Ask
}

func Display(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if a == "" || strings.ContainsAny(a, " \t'\"\\$`;&|<>()*?[]{}~#!") {
			out[i] = "'" + strings.ReplaceAll(a, "'", `'"'"'`) + "'"
			continue
		}
		out[i] = a
	}
	return strings.Join(out, " ")
}

type Answer int

const (
	No Answer = iota
	Once
	Always
)

func ParseAnswer(s string) Answer {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "y", "yes", "o", "oui":
		return Once
	case "a", "always", "t", "toujours":
		return Always
	}
	return No
}
