package template

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/agardenat/clotr/internal/driver/ssh"
)

type Template struct {
	Name        string               `yaml:"name"`
	Version     int                  `yaml:"version"`
	Description string               `yaml:"description"`
	Params      map[string]Param     `yaml:"params"`
	Connectors  map[string]Connector `yaml:"connectors"`
	Targets     []map[string]string  `yaml:"targets"`
	Script      string               `yaml:"script"`
	Files       []string             `yaml:"files"`
	Env         []string             `yaml:"env"`
	Tools       []ToolSpec           `yaml:"tools"`
	Companions  []string             `yaml:"companions"`
	SSHPaths    ssh.PathRules        `yaml:"ssh_paths"`
	Hints       string               `yaml:"hints"`

	Source     string `yaml:"-"`
	Raw        []byte `yaml:"-"`
	ScriptPath string `yaml:"-"`
	ScriptSrc  []byte `yaml:"-"`
}

type Param struct {
	Type        string            `yaml:"type"`
	Required    bool              `yaml:"required"`
	Default     any               `yaml:"default"`
	Values      []string          `yaml:"values"`
	Item        map[string]string `yaml:"item"`
	Description string            `yaml:"description"`
}

type Connector struct {
	Driver  string         `yaml:"driver"`
	Options map[string]any `yaml:",inline"`
}

type ToolSpec struct {
	Kind        string `yaml:"kind"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

var (
	nameRe      = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	identRe     = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	paramTypes  = []string{"string", "url", "int", "bool", "env", "path", "enum", "list"}
	itemTypes   = []string{"string", "url", "int", "bool", "path"}
	drivers     = []string{"http", "ssh"}
	targetKinds = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	envNameRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

func Parse(data []byte, source string) (*Template, error) {
	var t Template
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("template %s: %w", source, err)
	}
	t.Source, t.Raw = source, data
	if t.Script != "" {
		p := t.Script
		if !filepath.IsAbs(p) {
			p = filepath.Join(filepath.Dir(source), p)
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("template %s: script: %w", source, err)
		}
		t.ScriptPath, t.ScriptSrc = p, src
	}
	if err := t.validate(); err != nil {
		return nil, fmt.Errorf("template %s: %w", source, err)
	}
	return &t, nil
}

func (t *Template) validate() error {
	var errs []string
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}
	if !nameRe.MatchString(t.Name) {
		fail("name: %q invalide ([a-z][a-z0-9-]*)", t.Name)
	}
	for _, n := range sortedKeys(t.Params) {
		p := t.Params[n]
		if !slices.Contains(paramTypes, p.Type) {
			fail("params.%s.type: %q invalide (%s)", n, p.Type, strings.Join(paramTypes, "|"))
		}
		if p.Type == "enum" && len(p.Values) == 0 {
			fail("params.%s.values: requis pour enum", n)
		}
		if p.Type == "list" {
			if len(p.Item) == 0 {
				fail("params.%s.item: requis pour list", n)
			}
			for k, it := range p.Item {
				if !slices.Contains(itemTypes, it) {
					fail("params.%s.item.%s: type %q invalide (%s)", n, k, it, strings.Join(itemTypes, "|"))
				}
			}
		}
	}
	nssh := 0
	for _, n := range sortedKeys(t.Connectors) {
		c := t.Connectors[n]
		if !identRe.MatchString(n) {
			fail("connectors.%s: nom invalide ([a-z][a-z0-9_]*)", n)
		}
		if !slices.Contains(drivers, c.Driver) {
			fail("connectors.%s.driver: %q inconnu (%s)", n, c.Driver, strings.Join(drivers, "|"))
		}
		if c.Driver == "ssh" {
			nssh++
		}
		if c.Driver == "http" {
			if err := checkHTTPOptions(options(c.Options)); err != nil {
				fail("connectors.%s: %v", n, err)
			}
		}
	}
	if nssh > 1 {
		fail("connectors: un seul connecteur ssh par template")
	}
	for i, tg := range t.Targets {
		if !targetKinds.MatchString(tg["kind"]) {
			fail("targets[%d].kind: %q invalide", i, tg["kind"])
		}
		if fe := tg["foreach"]; fe != "" {
			if p, ok := t.Params[fe]; !ok || p.Type != "list" {
				fail("targets[%d].foreach: %q n'est pas un paramètre de type list", i, fe)
			}
			if tg["name"] == "" {
				fail("targets[%d].name: requis avec foreach", i)
			}
		}
	}
	if len(t.Targets) == 0 && t.Script == "" {
		fail("targets ou script: au moins l'un des deux est requis")
	}
	for i, e := range t.Env {
		if !envNameRe.MatchString(e) {
			fail("env[%d]: nom de variable %q invalide", i, e)
		}
	}
	for i, f := range t.Files {
		if strings.TrimSpace(f) == "" {
			fail("files[%d]: chemin vide", i)
		}
	}
	seen := map[string]bool{}
	for i, ts := range t.Tools {
		k, ok := kinds[ts.Kind]
		if !ok {
			fail("tools[%d].kind: %q inconnu (%s)", i, ts.Kind, strings.Join(sortedKeys(kinds), ", "))
			continue
		}
		if k.ssh && nssh == 0 {
			fail("tools[%d] (%s): exige un connecteur de driver ssh", i, ts.Kind)
		}
		name := ts.ToolName()
		if !identRe.MatchString(name) {
			fail("tools[%d].name: %q invalide", i, name)
		}
		if seen[name] {
			fail("tools[%d].name: %q dupliqué", i, name)
		}
		seen[name] = true
	}
	if nssh > 0 {
		if _, err := ssh.CompileRules(t.SSHPaths); err != nil {
			fail("%v", err)
		}
	}
	if t.ScriptSrc != nil {
		if err := checkScript(t); err != nil {
			fail("script %s: %v", t.Script, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (t *Template) sshConnector() (string, Connector, bool) {
	for _, n := range sortedKeys(t.Connectors) {
		if c := t.Connectors[n]; c.Driver == "ssh" {
			return n, c, true
		}
	}
	return "", Connector{}, false
}

func (ts ToolSpec) ToolName() string {
	if ts.Name != "" {
		return ts.Name
	}
	return ts.Kind
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
