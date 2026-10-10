package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/agardenat/clotr/internal/llm"
)

type Tool interface {
	Name() string
	Description() string
	Schema() json.RawMessage
	Call(ctx context.Context, args json.RawMessage) (string, error)
}

type Registry struct {
	tools      map[string]Tool
	order      []string
	maxChars   int
	companions map[string][]string
	groups     []string
}

func NewRegistry(maxChars int) *Registry {
	return &Registry{tools: map[string]Tool{}, maxChars: maxChars}
}

func (r *Registry) Add(ts ...Tool) {
	for _, t := range ts {
		if _, dup := r.tools[t.Name()]; dup {
			panic("outil dupliqué: " + t.Name())
		}
		r.tools[t.Name()] = t
		r.order = append(r.order, t.Name())
	}
}

func (r *Registry) AddCompanions(prefix string, names ...string) {
	if r.companions == nil {
		r.companions = map[string][]string{}
	}
	r.companions[prefix] = append(r.companions[prefix], names...)
}

func (r *Registry) AddGroup(prefix string) {
	if !slices.Contains(r.groups, prefix) {
		r.groups = append(r.groups, prefix)
	}
}

func (r *Registry) Without(prefixes ...string) *Registry {
	hidden := func(name string) bool {
		return slices.ContainsFunc(prefixes, func(p string) bool {
			p = strings.TrimSuffix(p, "_")
			return name == p || strings.HasPrefix(name, p+"_")
		})
	}
	out := &Registry{tools: map[string]Tool{}, maxChars: r.maxChars, companions: map[string][]string{}}
	for _, n := range r.order {
		if !hidden(n) {
			out.tools[n] = r.tools[n]
			out.order = append(out.order, n)
		}
	}
	for _, g := range r.groups {
		if !hidden(g) {
			out.groups = append(out.groups, g)
		}
	}
	for p, names := range r.companions {
		if !hidden(p) {
			out.companions[p] = names
		}
	}
	return out
}

func (r *Registry) GroupMembers(selected []string) []string {
	var out []string
	for _, prefix := range r.groups {
		if !slices.ContainsFunc(selected, func(s string) bool { return strings.HasPrefix(s, prefix) }) {
			continue
		}
		for _, n := range r.order {
			if strings.HasPrefix(n, prefix) && !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
	}
	return out
}

func (r *Registry) Companions(selected []string) []string {
	var out []string
	for prefix, names := range r.companions {
		for _, s := range selected {
			if strings.HasPrefix(s, prefix) {
				for _, n := range names {
					if _, ok := r.tools[n]; ok && !slices.Contains(out, n) {
						out = append(out, n)
					}
				}
				break
			}
		}
	}
	slices.Sort(out)
	return out
}

func (r *Registry) Names() []string {
	return append([]string(nil), r.order...)
}

func (r *Registry) Len() int {
	return len(r.order)
}

func (r *Registry) Expand(names []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if _, ok := r.tools[n]; ok {
			add(n)
			continue
		}
		prefix := strings.TrimSuffix(strings.TrimSuffix(n, "*"), "_") + "_"
		matched := false
		for _, name := range r.order {
			if strings.HasPrefix(name, prefix) {
				add(name)
				matched = true
			}
		}
		if !matched {
			return nil, fmt.Errorf("outil inconnu %q", n)
		}
	}
	return out, nil
}

func (r *Registry) Defs(names []string) []llm.ToolDef {
	var out []llm.ToolDef
	for _, n := range names {
		t, ok := r.tools[n]
		if !ok {
			continue
		}
		out = append(out, llm.ToolDef{Type: "function", Function: llm.FunctionDef{Name: t.Name(), Description: t.Description(), Parameters: t.Schema()}})
	}
	return out
}

func (r *Registry) Description(name string) string {
	t, ok := r.tools[name]
	if !ok {
		return ""
	}
	desc, _, _ := strings.Cut(t.Description(), "\n")
	return desc
}

func (r *Registry) Describe() string {
	var b strings.Builder
	for _, n := range r.order {
		desc, _, _ := strings.Cut(r.tools[n].Description(), "\n")
		fmt.Fprintf(&b, "- %s: %s\n", n, desc)
	}
	return b.String()
}

func (r *Registry) Call(ctx context.Context, allowed []string, name, args string) (string, error) {
	permitted := false
	for _, a := range allowed {
		if a == name {
			permitted = true
			break
		}
	}
	t, ok := r.tools[name]
	if !ok || !permitted {
		return "", fmt.Errorf("outil %q non disponible pour cette tâche", name)
	}
	if strings.TrimSpace(args) == "" {
		args = "{}"
	}
	if !json.Valid([]byte(args)) {
		return "", fmt.Errorf("arguments JSON invalides pour %s", name)
	}
	out, err := t.Call(ctx, json.RawMessage(args))
	if err != nil {
		return "", err
	}
	return Truncate(out, r.maxChars), nil
}

func Truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	rest := s[cut:]
	return s[:cut] + fmt.Sprintf("\n[truncated: %d octets / %d lignes omis — affiner la requête]", len(rest), strings.Count(rest, "\n")+1)
}

func Decode[T any](args json.RawMessage) (T, error) {
	var v T
	if len(args) == 0 {
		return v, nil
	}
	if err := json.Unmarshal(args, &v); err != nil {
		return v, fmt.Errorf("arguments invalides: %w", err)
	}
	return v, nil
}

type StringList []string

func (l *StringList) UnmarshalJSON(data []byte) error {
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*l = arr
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("liste de chaînes attendue")
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	*l = out
	return nil
}
