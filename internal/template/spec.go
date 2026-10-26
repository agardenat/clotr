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

	"github.com/agardenat/clotr/internal/access"
	"github.com/agardenat/clotr/internal/driver/ssh"
	"github.com/agardenat/clotr/internal/i18n"
)

type Template struct {
	Name        string               `yaml:"name"`
	Version     int                  `yaml:"version"`
	Description string               `yaml:"description"`
	Keywords    []string             `yaml:"keywords"`
	Params      map[string]Param     `yaml:"params"`
	Connectors  map[string]Connector `yaml:"connectors"`
	Targets     []map[string]string  `yaml:"targets"`
	Script      string               `yaml:"script"`
	Files       []string             `yaml:"files"`
	Env         []string             `yaml:"env"`
	Tools       []ToolSpec           `yaml:"tools"`
	Companions  []string             `yaml:"companions"`
	SSHPaths    ssh.PathRules        `yaml:"ssh_paths"`
	Commands    access.Rules         `yaml:"commands"`
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
	When    string         `yaml:"when"`
	Options map[string]any `yaml:",inline"`
}

type ToolSpec struct {
	Kind        string `yaml:"kind"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	When        string `yaml:"when"`
}

var (
	nameRe      = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	identRe     = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	paramTypes  = []string{"string", "url", "int", "bool", "env", "path", "enum", "list"}
	itemTypes   = []string{"string", "url", "int", "bool", "path"}
	drivers     = []string{"http", "ssh", "local", "shell"}
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
	fail := func(msg string) {
		errs = append(errs, msg)
	}
	if !nameRe.MatchString(t.Name) {
		fail(i18n.T("tpl.spec.name", t.Name))
	}
	for _, n := range sortedKeys(t.Params) {
		p := t.Params[n]
		if !slices.Contains(paramTypes, p.Type) {
			fail(i18n.T("tpl.spec.param_type", n, p.Type, strings.Join(paramTypes, "|")))
		}
		if p.Type == "enum" && len(p.Values) == 0 {
			fail(i18n.T("tpl.spec.enum_values", n))
		}
		if p.Type == "list" {
			if len(p.Item) == 0 {
				fail(i18n.T("tpl.spec.list_item", n))
			}
			for k, it := range p.Item {
				if !slices.Contains(itemTypes, it) {
					fail(i18n.T("tpl.spec.item_type", n, k, it, strings.Join(itemTypes, "|")))
				}
			}
		}
	}
	nssh := 0
	for _, n := range sortedKeys(t.Connectors) {
		c := t.Connectors[n]
		if !identRe.MatchString(n) {
			fail(i18n.T("tpl.spec.connector", n))
		}
		if !slices.Contains(drivers, c.Driver) {
			fail(i18n.T("tpl.spec.driver", n, c.Driver, strings.Join(drivers, "|")))
		}
		if c.Driver == "ssh" {
			nssh++
			if err := checkAuthOptions(options(c.Options)); err != nil {
				fail(fmt.Sprintf("connectors.%s: %v", n, err))
			}
		}
		if c.Driver == "local" {
			nssh++
			for k := range c.Options {
				if k != "max_conns" {
					fail(i18n.T("tpl.spec.local_option", n, k))
				}
			}
		}
		if c.Driver == "shell" {
			nssh++
			for k := range c.Options {
				if !slices.Contains([]string{"command", "ready", "prompt", "open_timeout", "max_conns", "sudo"}, k) {
					fail(i18n.T("tpl.spec.shell_option", n, k))
				}
			}
			if len(options(c.Options).list("command")) == 0 {
				fail(i18n.T("tpl.spec.shell_command", n))
			}
		}
		if c.Driver == "http" {
			if err := checkHTTPOptions(options(c.Options)); err != nil {
				fail(fmt.Sprintf("connectors.%s: %v", n, err))
			}
		}
	}
	if nssh > 1 {
		fail(i18n.T("tpl.spec.one_ssh"))
	}
	for i, tg := range t.Targets {
		if !targetKinds.MatchString(tg["kind"]) {
			fail(i18n.T("tpl.spec.target_kind", i, tg["kind"]))
		}
		if fe := tg["foreach"]; fe != "" {
			if p, ok := t.Params[fe]; !ok || p.Type != "list" {
				fail(i18n.T("tpl.spec.foreach", i, fe))
			}
			if tg["name"] == "" {
				fail(i18n.T("tpl.spec.foreach_name", i))
			}
		}
	}
	if len(t.Targets) == 0 && t.Script == "" {
		fail(i18n.T("tpl.spec.targets_script"))
	}
	for i, e := range t.Env {
		if !envNameRe.MatchString(e) {
			fail(i18n.T("tpl.spec.env", i, e))
		}
	}
	for i, f := range t.Files {
		if strings.TrimSpace(f) == "" {
			fail(i18n.T("tpl.spec.file", i))
		}
	}
	seen := map[string]bool{}
	for i, ts := range t.Tools {
		k, ok := kinds[ts.Kind]
		if !ok {
			fail(i18n.T("tpl.spec.tool_kind", i, ts.Kind, strings.Join(sortedKeys(kinds), ", ")))
			continue
		}
		if k.ssh && nssh == 0 {
			fail(i18n.T("tpl.spec.tool_ssh", i, ts.Kind))
		}
		name := ts.ToolName()
		if !identRe.MatchString(name) {
			fail(i18n.T("tpl.spec.tool_name", i, name))
		}
		if seen[name] {
			fail(i18n.T("tpl.spec.tool_dup", i, name))
		}
		seen[name] = true
	}
	if nssh > 0 {
		if err := checkPaths(t.SSHPaths); err != nil {
			fail(err.Error())
		}
	}
	if _, err := access.CompileCommands(t.Commands); err != nil {
		fail("commands: " + err.Error())
	}
	if t.ScriptSrc != nil {
		if err := checkScript(t); err != nil {
			fail(fmt.Sprintf("script %s: %v", t.Script, err))
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
