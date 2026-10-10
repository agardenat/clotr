package template

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"github.com/agardenat/clotr/internal/config"
)

var envRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (t *Template) ResolveParams(given map[string]any) (map[string]any, error) {
	var errs []string
	out := map[string]any{}
	for k := range given {
		if _, ok := t.Params[k]; !ok {
			errs = append(errs, fmt.Sprintf("paramètre %q inconnu du template %s (connus: %s)", k, t.Name, strings.Join(sortedKeys(t.Params), ", ")))
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
				errs = append(errs, fmt.Sprintf("paramètre %q requis", name))
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
		return nil, fmt.Errorf("paramètre %q: liste attendue", name)
	}
	out := make([]map[string]any, 0, len(raw))
	for i, r := range raw {
		m, ok := r.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("paramètre %s[%d]: objet attendu", name, i)
		}
		cm := map[string]any{}
		for k, val := range m {
			typ, ok := item[k]
			if !ok {
				return nil, fmt.Errorf("paramètre %s[%d].%s inconnu (connus: %s)", name, i, k, strings.Join(sortedKeys(item), ", "))
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
				return nil, fmt.Errorf("paramètre %q: entier attendu, %q", name, n)
			}
			return i, nil
		}
		return nil, fmt.Errorf("paramètre %q: entier attendu, %v", name, v)
	case "bool":
		if b, ok := v.(bool); ok {
			return b, nil
		}
		b, err := strconv.ParseBool(s)
		if err != nil {
			return nil, fmt.Errorf("paramètre %q: booléen attendu, %v", name, v)
		}
		return b, nil
	case "url":
		if s == "" {
			return s, nil
		}
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("paramètre %q: URL invalide %q", name, s)
		}
		return s, nil
	case "env":
		if s != "" && !envRe.MatchString(s) {
			return nil, fmt.Errorf("paramètre %q: nom de variable d'environnement attendu, pas une valeur", name)
		}
		return s, nil
	case "path":
		return config.ExpandHome(s), nil
	case "enum":
		if !slices.Contains(values, s) {
			return nil, fmt.Errorf("paramètre %q: %q invalide (%s)", name, s, strings.Join(values, "|"))
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
		return 0, fmt.Errorf("option %s: entier attendu, %q", k, s)
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
		return false, fmt.Errorf("option %s: booléen attendu, %q", k, s)
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
