package config

import (
	"os"
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
		"providers: []\n": "au moins un provider",
		"providers:\n  - name: a\n    base_url: nope\n":                                          "URL invalide",
		"providers:\n  - name: a\n    base_url: http://x\nroles:\n  planner: {tier: huge}\n":     "tier",
		"providers:\n  - name: a\n    base_url: http://x\nunknown: 1\n":                          "unknown",
		"providers:\n  - name: a\n    base_url: http://x\nmcp:\n  - name: m\n":                   "command ou url",
		"providers:\n  - name: a\n    base_url: http://x\nlimits:\n  agent_timeout: 5 minutes\n": "invalid duration",
		"providers:\n  - name: a\n    base_url: http://x\nweb_search: {policy: maybe}\n":         "web_search.policy",
		"providers:\n  - name: a\n    base_url: http://x\nweb_search: {mcp: absent}\n":           "web_search.mcp",
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
	if err == nil || strings.Contains(err.Error(), "sk-1234") || !strings.Contains(err.Error(), "nom de variable") {
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
		"instances:\n  - name: k8s\n    template: x\n",
		"instances:\n  - name: a\n    template: x\n  - name: a\n    template: x\n",
		"instances:\n  - name: a\n",
	} {
		if _, err := Parse([]byte(base + bad)); err == nil {
			t.Errorf("accepté:\n%s", bad)
		}
	}
}
