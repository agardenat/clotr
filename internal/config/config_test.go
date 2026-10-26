package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseExample(t *testing.T) {
	data, err := os.ReadFile("../../clotr.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Providers) != 4 || c.Providers[0].MaxConcurrency != 4 {
		t.Fatalf("providers: %+v", c.Providers)
	}
	if c.Limits.AgentTimeout.Duration != 0 || *c.Limits.StallSteps != 3 {
		t.Fatalf("agent_timeout / stall_steps: %v %d", c.Limits.AgentTimeout, *c.Limits.StallSteps)
	}
	if len(c.MCP) == 0 || c.MCP[0].Transport == "" {
		t.Fatalf("mcp: %+v", c.MCP)
	}
}

func TestDefaults(t *testing.T) {
	c, err := Parse([]byte("providers:\n  - name: a\n    base_url: http://x/v1/\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Providers[0].BaseURL != "http://x/v1" {
		t.Fatalf("base_url non normalisée: %s", c.Providers[0].BaseURL)
	}
	if _, ok := c.Roles[RolePlanner]; !ok || len(c.WorkerRoles()) == 0 {
		t.Fatal("rôles par défaut absents")
	}
	if c.Limits.MaxSteps != 100 || *c.Limits.StallSteps != 3 || c.Limits.AgentTimeout.Duration != 0 || c.Catalog.CacheTTL.Duration != time.Hour {
		t.Fatalf("limits: %+v", c.Limits)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string]string{
		"providers: []\n": "at least one provider",
		"providers:\n  - name: a\n    base_url: nope\n":                                                                                        "invalid URL",
		"providers:\n  - name: a\n    base_url: http://x\nroles:\n  planner: {tier: huge}\n":                                                   "tier",
		"providers:\n  - name: a\n    base_url: http://x\nunknown: 1\n":                                                                        "unknown",
		"providers:\n  - name: a\n    base_url: http://x\nmcp:\n  - name: m\n":                                                                 "command or url",
		"providers:\n  - name: a\n    base_url: http://x\nlimits:\n  agent_timeout: 5 minutes\n":                                               "invalid duration",
		"providers:\n  - name: a\n    base_url: http://x\nweb_search: {policy: maybe}\n":                                                       "web_search.policy",
		"providers:\n  - name: a\n    base_url: http://x\nweb_search: {mcp: absent}\n":                                                         "web_search.mcp",
		"providers:\n  - name: a\n    base_url: http://x\nweb_search: {model: b/m, api: messages}\n":                                           "web_search.model",
		"providers:\n  - name: a\n    base_url: http://x\nweb_search: {model: a/, api: messages}\n":                                            "web_search.model",
		"providers:\n  - name: a\n    base_url: http://x\nweb_search: {model: a/m}\n":                                                          "web_search.api",
		"providers:\n  - name: a\n    base_url: http://x\nweb_search: {api: responses}\n":                                                      "web_search.api",
		"providers:\n  - name: a\n    base_url: http://x\ninstances:\n  - {name: web, template: t}\n":                                          "is reserved",
		"providers:\n  - name: a\n    base_url: http://x\nreport_export: {mcp: absent}\n":                                                      "report_export.mcp",
		"providers:\n  - name: a\n    base_url: http://x\nmcp:\n  - {name: m, url: http://m}\nweb_search: {mcp: m}\nreport_export: {mcp: m}\n": "already the web_search",
		"providers:\n  - name: a\n    base_url: http://x\nmcp:\n  - {name: m, url: http://m}\nreport_export: {mcp: m, role: planner}\n":        "report_export.role",
	}
	for in, want := range cases {
		_, err := Parse([]byte(in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: erreur %v, attendu %q", in, err, want)
		}
	}
}

func TestAPIKey(t *testing.T) {
	t.Setenv("CLOTR_T_KEY", "sk-env")
	c, err := Parse([]byte("providers:\n  - {name: a, base_url: http://x, api_key: sk-lit}\n  - {name: b, base_url: http://x, api_key: \"${CLOTR_T_KEY}\"}\n  - {name: c, base_url: http://x, api_key_env: CLOTR_T_KEY}\n"))
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"sk-lit", "sk-env", "sk-env"} {
		if got := c.Providers[i].APIKey(); got != want {
			t.Errorf("%s: %q, attendu %q", c.Providers[i].Name, got, want)
		}
	}
	_, err = Parse([]byte("providers:\n  - {name: a, base_url: http://x, api_key_env: sk-1234-abcd}\n"))
	if err == nil || strings.Contains(err.Error(), "sk-1234") || !strings.Contains(err.Error(), "environment variable name") {
		t.Errorf("clé dans api_key_env: %v", err)
	}
}

func TestInstances(t *testing.T) {
	base := "providers:\n  - name: a\n    base_url: http://x/v1\n"
	c, err := Parse([]byte(base + "instances:\n  - name: prod\n    template: fixture\n    params: {api_url: https://x}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Instances[0].Params["api_url"] != "https://x" || !c.Instances[0].IsEnabled() || c.Templates.CacheTTL.Duration != 15*time.Minute || c.Templates.Dir == "" {
		t.Fatalf("instances: %+v %+v", c.Instances, c.Templates)
	}
	for _, bad := range []string{
		"instances:\n  - name: Bad\n    template: x\n",
		"instances:\n  - name: fs\n    template: x\n",
		"instances:\n  - name: a\n    template: x\n  - name: a\n    template: x\n",
		"instances:\n  - name: a\n",
	} {
		if _, err := Parse([]byte(base + bad)); err == nil {
			t.Errorf("accepté:\n%s", bad)
		}
	}
}

func TestClients(t *testing.T) {
	base := "providers:\n  - name: a\n    base_url: http://x/v1\ninstances:\n  - {name: solo, template: x}\n"
	load := func(clients map[string]string) (*Config, error) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "clients"), 0o700); err != nil {
			t.Fatal(err)
		}
		for name, body := range clients {
			if err := os.WriteFile(filepath.Join(dir, "clients", name+".yaml"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte(base), 0o600); err != nil {
			t.Fatal(err)
		}
		return Load(path)
	}
	c, err := load(map[string]string{
		"acme": "name: acme\naliases: [acmecorp]\ncontext: client fictif\nvars: {cmp: CMP-0000, project_code: PRJ-0000}\nparams: {proxy_url: socks5h://localhost:1080}\ninstances:\n  - {name: acme-lake, template: x}\n",
		"beta": "name: beta\ninstances:\n  - {name: beta-lake, template: x}\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Instances) != 3 || c.Instances[0].Client != "" || c.Instances[1].Client != "acme" || c.Instances[2].Client != "beta" {
		t.Fatalf("instances: %+v", c.Instances)
	}
	if cl, ok := c.Client("acme"); !ok || cl.Params["proxy_url"] != "socks5h://localhost:1080" || cl.Aliases[0] != "acmecorp" || cl.Instances != nil || cl.Vars["project_code"] != "PRJ-0000" {
		t.Fatalf("client: %+v", cl)
	}
	c, err = load(map[string]string{"acme": "name: acme\nprojects:\n  - name: PRJ-0001\n    aliases: [lake]\n    vars: {site: s1}\n    params: {zone: z1}\n    instances:\n      - {name: acme-lake, template: x}\n  - name: PRJ-0002\n    instances:\n      - {name: acme-pra, template: x}\ninstances:\n  - {name: acme-shared, template: x}\n"})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Instances) != 4 || c.Instances[1].Name != "acme-shared" || c.Instances[1].Project != "" || c.Instances[2].Project != "PRJ-0001" || c.Instances[2].Client != "acme" || c.Instances[3].Project != "PRJ-0002" {
		t.Fatalf("instances des projets: %+v", c.Instances)
	}
	if p, ok := c.Clients[0].Project("PRJ-0001"); !ok || p.Instances != nil || p.Vars["site"] != "s1" || p.Params["zone"] != "z1" || p.Aliases[0] != "lake" {
		t.Fatalf("projet: %+v", p)
	}
	if c, err := load(map[string]string{"acme": "name: acme\naccess: exec\ninstances:\n  - {name: acme-lake, template: x}\n"}); err != nil || c.Clients[0].Access != "exec" {
		t.Fatalf("access: %v", err)
	}
	if _, err := load(map[string]string{"acme": "name: acme\naccess: root\ninstances:\n  - {name: acme-lake, template: x}\n"}); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("access invalide accepté: %v", err)
	}
	for name, bad := range map[string]map[string]string{
		"nom différent du fichier":     {"acme": "name: other\n"},
		"nom d'instance":               {"solo": "name: solo\n"},
		"nom réservé":                  {"fs": "name: fs\n"},
		"alias en double":              {"acme": "name: acme\naliases: [shared]\n", "beta": "name: beta\naliases: [Shared]\n"},
		"alias vide":                   {"acme": "name: acme\naliases: [\"\"]\n"},
		"champ inconnu":                {"acme": "name: acme\nproxy: x\n"},
		"instance en double":           {"acme": "name: acme\ninstances:\n  - {name: solo, template: x}\n"},
		"variable invalide":            {"acme": "name: acme\nvars: {Cmp: x}\n"},
		"variable vide":                {"acme": "name: acme\nvars: {cmp: \" \"}\n"},
		"projet sans nom":              {"acme": "name: acme\nprojects:\n  - {aliases: [x]}\n"},
		"projet en double":             {"acme": "name: acme\nprojects:\n  - {name: PRJ-1}\n  - {name: prj-1}\n"},
		"projet = alias client":        {"acme": "name: acme\naliases: [lake]\nprojects:\n  - {name: PRJ-1, aliases: [Lake]}\n"},
		"projet d'un autre client":     {"acme": "name: acme\nprojects:\n  - {name: PRJ-1}\n", "beta": "name: beta\nprojects:\n  - {name: PRJ-1}\n"},
		"variable de projet":           {"acme": "name: acme\nprojects:\n  - {name: PRJ-1, vars: {Site: x}}\n"},
		"champ de projet inconnu":      {"acme": "name: acme\nprojects:\n  - {name: PRJ-1, hosts: []}\n"},
		"instance de projet en double": {"acme": "name: acme\nprojects:\n  - name: PRJ-1\n    instances:\n      - {name: solo, template: x}\n"},
	} {
		if _, err := load(bad); err == nil {
			t.Errorf("%s: accepté", name)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := Load(path); err != nil || len(c.Clients) != 0 {
		t.Fatalf("sans répertoire clients: %v %+v", err, c)
	}
}

func TestVaultConf(t *testing.T) {
	base := "providers:\n  - name: a\n    base_url: http://x/v1\n"
	c, err := Parse([]byte(base + "vault: {addr: https://vault.example.com, namespace: team}\n"))
	if err != nil || c.Vault.Addr != "https://vault.example.com" || c.Vault.Namespace != "team" {
		t.Fatalf("vault: %v %+v", err, c)
	}
	if _, err := Parse([]byte(base + "vault: {addr: vault.example.com}\n")); err == nil {
		t.Error("vault.addr sans schéma accepté")
	}
}

func TestExportRole(t *testing.T) {
	c, err := Parse([]byte("providers:\n  - name: a\n    base_url: http://x\nmcp:\n  - {name: docs, url: http://d}\nreport_export: {mcp: docs}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.ExportRole(); got != "analyst" {
		t.Fatalf("rôle par défaut: %q", got)
	}
	c.Export.Role = "collector"
	if got := c.ExportRole(); got != "collector" {
		t.Fatalf("rôle configuré: %q", got)
	}
}
