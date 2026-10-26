package template

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/driver/ssh"
	"github.com/agardenat/clotr/internal/i18n"
)

var envRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (t *Template) ResolveParams(given map[string]any) (map[string]any, error) {
	var errs []string
	out := map[string]any{}
	for k := range given {
		if _, ok := t.Params[k]; !ok {
			errs = append(errs, i18n.T("tpl.param.unknown", k, t.Name, strings.Join(sortedKeys(t.Params), ", ")))
		}
	}
	for _, name := range sortedKeys(t.Params) {
		p := t.Params[name]
		v, ok := given[name]
		if !ok || v == nil {
			v = p.Default
		}
		if v == nil {
			if p.Required {
				errs = append(errs, i18n.T("tpl.param.required", name))
			}
			if p.Type == "list" {
				out[name] = []map[string]any{}
			} else {
				out[name] = ""
			}
			continue
		}
		if p.Type == "list" {
			items, err := convertList(name, v, p.Item)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			out[name] = items
			continue
		}
		cv, err := convert(name, p.Type, v, p.Values)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		out[name] = cv
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return out, nil
}

func convertList(name string, v any, item map[string]string) ([]map[string]any, error) {
	raw, ok := v.([]any)
	if !ok {
		return nil, i18n.E("tpl.param.list", name)
	}
	out := make([]map[string]any, 0, len(raw))
	for i, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			return nil, i18n.E("tpl.param.object", name, i)
		}
		cm := map[string]any{}
		for k, val := range m {
			typ, ok := item[k]
			if !ok {
				return nil, i18n.E("tpl.param.item_unknown", name, i, k, strings.Join(sortedKeys(item), ", "))
			}
			if val == nil {
				continue
			}
			cv, err := convert(fmt.Sprintf("%s[%d].%s", name, i, k), typ, val, nil)
			if err != nil {
				return nil, err
			}
			cm[k] = cv
		}
		for k := range item {
			if _, ok := cm[k]; !ok {
				cm[k] = ""
			}
		}
		out = append(out, cm)
	}
	return out, nil
}

func convert(name, typ string, v any, values []string) (any, error) {
	s := fmt.Sprint(v)
	switch typ {
	case "int":
		switch n := v.(type) {
		case int:
			return n, nil
		case string:
			if n == "" {
				return "", nil
			}
			i, err := strconv.Atoi(n)
			if err != nil {
				return nil, i18n.E("tpl.param.int_str", name, n)
			}
			return i, nil
		}
		return nil, i18n.E("tpl.param.int", name, v)
	case "bool":
		if b, ok := v.(bool); ok {
			return b, nil
		}
		b, err := strconv.ParseBool(s)
		if err != nil {
			return nil, i18n.E("tpl.param.bool", name, v)
		}
		return b, nil
	case "url":
		if s == "" {
			return s, nil
		}
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, i18n.E("tpl.param.url", name, s)
		}
		return s, nil
	case "env":
		if s != "" && !envRe.MatchString(s) {
			return nil, i18n.E("tpl.param.env", name)
		}
		return s, nil
	case "path":
		return config.ExpandHome(s), nil
	case "enum":
		if !slices.Contains(values, s) {
			return nil, i18n.E("tpl.param.enum", name, s, strings.Join(values, "|"))
		}
		return s, nil
	}
	return s, nil
}

func Render(s string, data map[string]any) (string, error) {
	if !strings.Contains(s, "{{") {
		return s, nil
	}
	tpl, err := template.New("").Option("missingkey=error").Parse(s)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := tpl.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

func renderPaths(r ssh.PathRules, data map[string]any) (ssh.PathRules, error) {
	render := func(field string, globs []string) ([]string, error) {
		var out []string
		for i, g := range globs {
			if !strings.Contains(g, "{{") {
				out = append(out, g)
				continue
			}
			v, err := Render(g, data)
			if err != nil {
				return nil, fmt.Errorf("ssh_paths.%s[%d]: %w", field, i, err)
			}
			if v = strings.TrimSpace(v); v == "" {
				continue
			}
			if strings.Contains(v, "..") || unsafePath.MatchString(v) {
				return nil, i18n.E("tpl.param.ssh_path", field, i, v)
			}
			out = append(out, path.Clean(v))
		}
		return out, nil
	}
	allow, err := render("allow", r.Allow)
	if err != nil {
		return r, err
	}
	deny, err := render("deny", r.Deny)
	if err != nil {
		return r, err
	}
	return ssh.PathRules{Allow: allow, Deny: deny}, nil
}

func (in *Instance) UseShell(s *config.Shell) error {
	if s == nil {
		return nil
	}
	if in.sshName == "" || in.local {
		return i18n.E("tpl.instance_shell_ssh", in.Name)
	}
	if len(s.Command) == 0 || strings.TrimSpace(s.Command[0]) == "" {
		return i18n.E("tpl.instance_shell_command", in.Name)
	}
	old := in.conns[in.sshName]
	cmd := make([]any, len(s.Command))
	for i, a := range s.Command {
		cmd[i] = a
	}
	o := options{"command": cmd, "sudo": old["sudo"], "max_conns": old["max_conns"], "open_timeout": old["open_timeout"], "ready": old["ready"], "prompt": old["prompt"]}
	for k, v := range map[string]string{"ready": s.Ready, "prompt": s.Prompt} {
		if v != "" {
			if _, err := regexp.Compile(v); err != nil {
				return fmt.Errorf("instance %s: shell: %w", in.Name, i18n.E("tpl.option.regexp", k, err))
			}
			o[k] = v
		}
	}
	if s.OpenTimeout > 0 {
		o["open_timeout"] = s.OpenTimeout
	}
	if s.MaxConns > 0 {
		o["max_conns"] = s.MaxConns
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.pool != nil {
		in.pool.Close()
		in.pool = nil
	}
	in.conns[in.sshName] = o
	in.shell = true
	return nil
}

func (in *Instance) ExtendPaths(extra config.PathRules) error {
	if len(extra.Allow) == 0 && len(extra.Deny) == 0 {
		return nil
	}
	if in.rules == nil {
		return i18n.E("tpl.instance_paths_ssh", in.Name)
	}
	src := in.rules.Source()
	merged := ssh.PathRules{Allow: slices.Clone(src.Allow), Deny: slices.Clone(src.Deny)}
	for field, globs := range map[string][]string{"allow": extra.Allow, "deny": extra.Deny} {
		for i, g := range globs {
			g = strings.TrimSpace(g)
			if g == "" || strings.Contains(g, "..") || unsafePath.MatchString(g) || strings.Contains(g, "{{") {
				return fmt.Errorf("instance %s: %w", in.Name, i18n.E("tpl.param.ssh_path", field, i, g))
			}
			if field == "allow" {
				merged.Allow = append(merged.Allow, path.Clean(g))
			} else {
				merged.Deny = append(merged.Deny, path.Clean(g))
			}
		}
	}
	rules, err := ssh.CompileRules(merged)
	if err != nil {
		return fmt.Errorf("instance %s: %w", in.Name, err)
	}
	in.rules = rules
	return nil
}

func checkPaths(r ssh.PathRules) error {
	static := ssh.PathRules{}
	for field, globs := range map[string][]string{"allow": r.Allow, "deny": r.Deny} {
		for i, g := range globs {
			if !strings.Contains(g, "{{") {
				if field == "allow" {
					static.Allow = append(static.Allow, g)
				} else {
					static.Deny = append(static.Deny, g)
				}
				continue
			}
			if _, err := template.New("").Parse(g); err != nil {
				return fmt.Errorf("ssh_paths.%s[%d]: %w", field, i, err)
			}
		}
	}
	if len(static.Allow) == 0 && len(r.Allow) > 0 {
		static.Allow = []string{"/"}
	}
	_, err := ssh.CompileRules(static)
	return err
}

var unsafePath = regexp.MustCompile("[\x00-\x1f\x7f]")

func renderAny(v any, data map[string]any) (any, error) {
	switch x := v.(type) {
	case string:
		return Render(x, data)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			r, err := renderAny(e, data)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			r, err := renderAny(e, data)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	}
	return v, nil
}

type options map[string]any

func (o options) str(k string) string {
	v, ok := o[k]
	if !ok || v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func (o options) int(k string, def int) (int, error) {
	s := o.str(k)
	if s == "" {
		return def, nil
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0, i18n.E("tpl.option.int", k, s)
	}
	return i, nil
}

func (o options) bool(k string, def bool) (bool, error) {
	s := o.str(k)
	if s == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		return false, i18n.E("tpl.option.bool", k, s)
	}
	return b, nil
}

func (o options) list(k string) []string {
	raw, ok := o[k].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, r := range raw {
		out = append(out, fmt.Sprint(r))
	}
	return out
}

func (o options) sub(k string) options {
	m, _ := o[k].(map[string]any)
	return options(m)
}
