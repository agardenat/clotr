package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/template"
	"github.com/agardenat/clotr/internal/tools"
)

func TestScopeHidesUnmentionedInstance(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte("name: acme\nkeywords: [widget]\ntargets:\n  - {kind: k, name: lake}\ntools:\n  - kind: inventory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := template.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	tpl, _ := set.Get("acme")
	in, err := template.NewInstance("lab", tpl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Defer(context.Background(), "", time.Hour, false); err != nil {
		t.Fatal(err)
	}
	rt := &app{cfg: &config.Config{}, registry: tools.NewRegistry(100), audit: audit.Nop(), instances: []*template.Instance{in}, baseEnv: []string{"- Fichiers locaux: /var/log"}, instanceEnv: map[string][]string{"lab": in.EnvironmentLines()}}
	rt.registry.Add(in.Tools()...)
	rt.registry.AddGroup(in.ToolPrefix())
	reg, env := rt.scope(nil, "pourquoi Alice ne fait plus partie du groupe Finance ?")
	if reg.Len() != 0 || !strings.Contains(env, "non proposée pour cette demande") || strings.Contains(env, "lake") {
		t.Fatalf("instance proposée sans mention: %v\n%s", reg.Names(), env)
	}
	if reg, env := rt.scope(nil, "santé du widget principal"); reg.Len() != 1 || !strings.Contains(env, "lake") {
		t.Fatalf("instance mentionnée non proposée: %v\n%s", reg.Names(), env)
	}
	if reg, _ := rt.scope([]string{"lab"}, "question sans rapport"); reg.Len() != 1 {
		t.Fatal("-t lab doit forcer l'instance")
	}
}

func TestWarnFilteredInstanceMentioned(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte("name: acme\nkeywords: [widget]\ntargets:\n  - {kind: k, name: lake}\ntools:\n  - kind: inventory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte("providers:\n  - {name: p, base_url: http://x}\nroles:\n  planner: {tier: deep}\n  collector: {tier: fast, tools: true}\n  synthesizer: {tier: deep}\ntemplates: {dir: " + dir + "}\ninstances:\n  - {name: lab, template: acme}\n  - {name: off, template: acme, enabled: false}\n  - {name: gone, template: acme}\n"))
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.Open(t.TempDir(), "audit")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	rt := &app{cfg: cfg, registry: tools.NewRegistry(100), audit: log}
	rt.setupInstances(context.Background(), &options{quiet: true}, toolFilter{only: []string{"fs"}, exclude: []string{"gone"}}, func(string, ...any) {})
	if len(rt.instances) != 0 || len(rt.filtered) != 1 || rt.filtered[0].Name != "lab" {
		t.Fatalf("instances %d, écartées par -t %d", len(rt.instances), len(rt.filtered))
	}
	rt.warnFiltered("le widget ne répond plus")
	rt.warnFiltered("question sans rapport")
	data, err := os.ReadFile(log.Path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), `"kind":"instance_filtered"`); n != 1 || !strings.Contains(string(data), `"match":"widget"`) {
		t.Fatalf("audit: %s", data)
	}
}

func TestScopeClients(t *testing.T) {
	dir := t.TempDir()
	tdir := filepath.Join(dir, "templates")
	if err := os.MkdirAll(filepath.Join(dir, "clients"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(tdir, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"templates/acme.yaml": "name: acme\nkeywords: [widget]\nparams:\n  region: {type: string, default: none}\n  zone: {type: string, default: none}\ntargets:\n  - {kind: k, name: lake}\ntools:\n  - kind: inventory\n",
		"clients/north.yaml":  "name: north\naliases: [northcorp]\ncontext: client fictif du nord\nparams: {region: eu, zone: z1, unknown_param: x}\ninstances:\n  - {name: north-widget, template: acme, params: {zone: z9}}\n",
		"clients/south.yaml":  "name: south\ninstances:\n  - {name: south-widget, template: acme}\n  - {name: south-off, template: acme, enabled: false}\n",
		"config.yaml":         "providers:\n  - {name: p, base_url: http://x}\nroles:\n  planner: {tier: deep}\n  collector: {tier: fast, tools: true}\n  synthesizer: {tier: deep}\ntemplates: {dir: " + tdir + "}\ninstances:\n  - {name: solo-widget, template: acme}\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := config.Load(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	rt := &app{cfg: cfg, registry: tools.NewRegistry(100), audit: audit.Nop()}
	rt.setupInstances(context.Background(), &options{quiet: true}, toolFilter{}, func(f string, a ...any) { t.Errorf(f, a...) })
	if len(rt.instances) != 3 {
		t.Fatalf("instances: %d", len(rt.instances))
	}
	if p := rt.instances[1].Params(); p["region"] != "eu" || p["zone"] != "z9" {
		t.Fatalf("params du client: %v", p)
	}
	if p := rt.instances[2].Params(); p["region"] != "none" {
		t.Fatalf("params d'un autre client: %v", p)
	}
	offered := func(forced []string, text string) string {
		reg, _ := rt.scope(forced, text)
		var groups []string
		for _, in := range rt.instances {
			if slices.ContainsFunc(reg.Names(), func(n string) bool { return strings.HasPrefix(n, in.ToolPrefix()) }) {
				groups = append(groups, in.Name)
			}
		}
		return strings.Join(groups, ",")
	}
	for _, c := range []struct {
		forced     []string
		text, want string
	}{
		{nil, "état chez northcorp", "north-widget"},
		{nil, "le widget de north est lent", "north-widget"},
		{nil, "le widget est lent", "solo-widget,north-widget,south-widget"},
		{nil, "widget de north et south-widget", "north-widget,south-widget"},
		{nil, "widget north, cible lake", "solo-widget,north-widget,south-widget"},
		{[]string{"south"}, "widget north", "north-widget,south-widget"},
		{nil, "question sans rapport", ""},
	} {
		if got := offered(c.forced, c.text); got != c.want {
			t.Errorf("%v %q: %s, attendu %s", c.forced, c.text, got, c.want)
		}
	}
	_, env := rt.scope(nil, "le widget de north")
	if !strings.Contains(env, "- Client north (northcorp) : client fictif du nord. Instances de ce client : north-widget.") || !strings.Contains(env, "la demande cite le client north") {
		t.Fatalf("environnement:\n%s", env)
	}
	if got := expandClients(cfg, []string{"fs", "south", "north-widget"}); strings.Join(got, ",") != "fs,south-widget,north-widget" {
		t.Fatalf("expandClients: %v", got)
	}
	if why := rt.instances[1].Mention("souci chez NorthCorp"); why != "client north" {
		t.Fatalf("Mention: %q", why)
	}
}
