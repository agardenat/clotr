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
	rt.setupInstances(context.Background(), &options{quiet: true}, toolFilter{only: []string{"fs"}, exclude: []string{"gone"}}, func(string) {})
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
		"templates/acme.yaml": "name: acme\nkeywords: [widget]\nparams:\n  region: {type: string, default: none}\n  zone: {type: string, default: none}\n  secret: {type: string, default: \"\"}\n  items: {type: list, item: {name: string}}\ntargets:\n  - {kind: k, name: lake}\ntools:\n  - kind: inventory\n",
		"clients/north.yaml":  "name: north\naliases: [northcorp]\ncontext: client fictif du nord.\nvars: {cmp: CMP-0000, project: PRJ-0000}\nparams: {region: eu, zone: z1, unknown_param: x}\ninstances:\n  - {name: north-widget, template: acme, params: {zone: z9, secret: \"kv/{{.cmp}}/{{.project}}/admin#password\", items: [{name: \"{{.cmp}}-a\"}]}}\n",
		"clients/south.yaml":  "name: south\ninstances:\n  - {name: south-widget, template: acme}\n  - {name: south-off, template: acme, enabled: false}\n  - {name: south-bad, template: acme, params: {secret: \"kv/{{.cmp}}\"}}\n",
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
	var warnings []string
	rt.setupInstances(context.Background(), &options{quiet: true}, toolFilter{}, func(m string) { warnings = append(warnings, m) })
	if len(rt.instances) != 3 || len(warnings) != 1 || !strings.Contains(warnings[0], "south-bad") || !strings.Contains(warnings[0], "params.secret") {
		t.Fatalf("instances: %d, avertissements: %q", len(rt.instances), warnings)
	}
	if p := rt.instances[1].Params(); p["region"] != "eu" || p["zone"] != "z9" || p["secret"] != "kv/CMP-0000/PRJ-0000/admin#password" {
		t.Fatalf("params du client: %v", p)
	}
	if items, _ := rt.instances[1].Params()["items"].([]map[string]any); len(items) != 1 || items[0]["name"] != "CMP-0000-a" {
		t.Fatalf("liste rendue: %v", rt.instances[1].Params()["items"])
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
	if !strings.Contains(env, "- Client north (northcorp) : client fictif du nord. Références : cmp=CMP-0000, project=PRJ-0000. Instances de ce client : north-widget.") || !strings.Contains(env, "la demande cite le client north") {
		t.Fatalf("environnement:\n%s", env)
	}
	if got := expandClients(cfg, []string{"fs", "south", "north-widget"}); strings.Join(got, ",") != "fs,south-widget,south-bad,north-widget" {
		t.Fatalf("expandClients: %v", got)
	}
	if why := rt.instances[1].Mention("souci chez NorthCorp"); why != "client north" {
		t.Fatalf("Mention: %q", why)
	}
}

func TestScopeProjects(t *testing.T) {
	dir := t.TempDir()
	tdir := filepath.Join(dir, "templates")
	for _, d := range []string{"clients", "templates"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"templates/acme.yaml": "name: acme\nkeywords: [widget]\nparams:\n  region: {type: string, default: none}\n  zone: {type: string, default: none}\n  secret: {type: string, default: \"\"}\ntargets:\n  - {kind: k, name: lake}\ntools:\n  - kind: inventory\n",
		"clients/north.yaml":  "name: north\ncontext: client fictif.\nvars: {cmp: CMP-0000, project: PRJ-OLD}\nparams: {region: eu, zone: z1}\ninstances:\n  - {name: north-shared, template: acme}\nprojects:\n  - name: PRJ-0001\n    aliases: [prod]\n    context: site principal.\n    params: {zone: z2}\n    instances:\n      - {name: north-main, template: acme, params: {secret: \"kv/{{.cmp}}/{{.project}}\"}}\n  - name: PRJ-0002\n    aliases: [pra]\n    vars: {project: PRJ-0002-B, site: s2}\n    params: {zone: z3, region: us}\n    instances:\n      - {name: north-pra, template: acme, params: {secret: \"kv/{{.project}}/{{.site}}\"}}\n",
		"config.yaml":         "providers:\n  - {name: p, base_url: http://x}\nroles:\n  planner: {tier: deep}\n  collector: {tier: fast, tools: true}\n  synthesizer: {tier: deep}\ntemplates: {dir: " + tdir + "}\n",
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
	rt.setupInstances(context.Background(), &options{quiet: true}, toolFilter{}, func(m string) { t.Error(m) })
	if len(rt.instances) != 3 {
		t.Fatalf("instances: %d", len(rt.instances))
	}
	if p := rt.instances[0].Params(); p["zone"] != "z1" || p["region"] != "eu" {
		t.Fatalf("instance hors projet: %v", p)
	}
	if p := rt.instances[1].Params(); p["zone"] != "z2" || p["region"] != "eu" || p["secret"] != "kv/CMP-0000/PRJ-0001" {
		t.Fatalf("params du projet: %v", p)
	}
	if p := rt.instances[2].Params(); p["zone"] != "z3" || p["region"] != "us" || p["secret"] != "kv/PRJ-0002-B/s2" {
		t.Fatalf("vars du projet: %v", p)
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
		{nil, "état chez north", "north-shared,north-main,north-pra"},
		{nil, "le widget du pra est lent", "north-shared,north-pra"},
		{nil, "PRJ-0001 et PRA", "north-shared,north-main,north-pra"},
		{nil, "souci sur prj-0001", "north-shared,north-main"},
		{[]string{"PRJ-0002"}, "question sans rapport", "north-pra"},
	} {
		if got := offered(c.forced, c.text); got != c.want {
			t.Errorf("%v %q: %s, attendu %s", c.forced, c.text, got, c.want)
		}
	}
	_, env := rt.scope(nil, "le widget de prod")
	for _, want := range []string{
		"- Client north : client fictif. Références : cmp=CMP-0000, project=PRJ-OLD. Instances de ce client : north-shared, north-main.",
		"- Projet PRJ-0001 du client north (prod) : site principal. Instances de ce projet : north-main.",
		"- Instance north-pra (template acme, projet PRJ-0002) : non proposée, la demande cite le projet PRJ-0001 du client north",
	} {
		if !strings.Contains(env, want) {
			t.Fatalf("environnement sans %q:\n%s", want, env)
		}
	}
	if why := rt.instances[2].Mention("bascule du PRA"); why != "projet PRJ-0002" {
		t.Fatalf("Mention: %q", why)
	}
}

func TestApplyVaultEnv(t *testing.T) {
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_NAMESPACE", "team-env")
	applyVaultEnv(config.VaultConf{Addr: "https://vault.example.com", Namespace: "team-conf"})
	if os.Getenv("VAULT_ADDR") != "https://vault.example.com" || os.Getenv("VAULT_NAMESPACE") != "team-env" {
		t.Fatalf("VAULT_ADDR=%q VAULT_NAMESPACE=%q", os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_NAMESPACE"))
	}
}

func TestComplianceConfidential(t *testing.T) {
	dir := t.TempDir()
	tdir := filepath.Join(dir, "templates")
	for _, d := range []string{"clients", "templates"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"templates/acme.yaml": "name: acme\nkeywords: [widget]\ntargets:\n  - {kind: k, name: lake}\ntools:\n  - kind: inventory\n",
		"clients/north.yaml":  "name: north\naliases: [northcorp]\ncompliance: regulated\nprojects:\n  - {name: PRJ-0001, instances: [{name: north-widget, template: acme}]}\n",
		"clients/south.yaml":  "name: south\ncompliance: audited\ninstances:\n  - {name: south-widget, template: acme}\n",
		"config.yaml":         "providers:\n  - {name: p, base_url: http://x}\nroles:\n  planner: {tier: deep}\n  collector: {tier: fast, tools: true}\n  synthesizer: {tier: deep}\ntemplates: {dir: " + tdir + "}\ncompliance:\n  regulated: {confidential: true}\n  audited: {}\n",
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
	for _, c := range []struct {
		forced    []string
		text      string
		sovereign string
		want      bool
	}{
		{nil, "le widget de northcorp", "", true},
		{nil, "projet PRJ-0001", "", true},
		{nil, "état de north-widget", "", true},
		{[]string{"north"}, "question", "", true},
		{[]string{"north-widget"}, "question", "", true},
		{nil, "le widget de south", "", false},
		{nil, "le widget est lent", "", false},
		{nil, "northern lights", "", false},
	} {
		o := &options{sovereign: c.sovereign}
		if err := o.applyCompliance(cfg, c.forced, c.text, false); err != nil || o.confidential != c.want || (o.sovereign == "require") != c.want {
			t.Errorf("%v %q: confidential=%v sovereign=%q %v", c.forced, c.text, o.confidential, o.sovereign, err)
		}
	}
	if err := (&options{sovereign: "any"}).applyCompliance(cfg, nil, "north", false); err == nil || !strings.Contains(err.Error(), "north") {
		t.Fatalf("--sovereign any accepté : %v", err)
	}
	rt := &app{cfg: cfg, registry: tools.NewRegistry(100), audit: audit.Nop()}
	rt.setupInstances(context.Background(), &options{quiet: true}, toolFilter{}, func(string) {})
	offered := func(text string) string {
		reg, env := rt.scope(nil, text)
		var groups []string
		for _, in := range rt.instances {
			if slices.ContainsFunc(reg.Names(), func(n string) bool { return strings.HasPrefix(n, in.ToolPrefix()) }) {
				groups = append(groups, in.Name)
			}
		}
		return strings.Join(groups, ",") + "|" + env
	}
	if got := offered("le widget est lent"); !strings.HasPrefix(got, "south-widget|") || !strings.Contains(got, "le client north impose un run confidentiel") {
		t.Fatalf("hors run confidentiel : %s", got)
	}
	rt.confidential = true
	if got := offered("le widget est lent"); !strings.HasPrefix(got, "north-widget,south-widget|") {
		t.Fatalf("run confidentiel : %s", got)
	}
}
