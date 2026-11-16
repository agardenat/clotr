package template

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/agardenat/clotr/internal/config"
)

type fakeRemote struct {
	remote string
	calls  *[]string
}

func (f fakeRemote) Name() string        { return "mcp_srv_" + f.remote }
func (f fakeRemote) Description() string { return "[MCP srv] " + f.remote }
func (f fakeRemote) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"q":{"type":"string"}}}`)
}
func (f fakeRemote) Remote() string { return f.remote }
func (f fakeRemote) Call(_ context.Context, raw json.RawMessage) (string, error) {
	*f.calls = append(*f.calls, f.remote+" "+string(raw))
	return "ok " + f.remote, nil
}

const mcpToolsYAML = `name: obs
description: observabilité par un serveur MCP
params:
  server: {type: string, default: ""}
connectors:
  dd:
    driver: mcp
    when: "{{if .server}}true{{end}}"
    server: "{{.server}}"
targets: [{kind: org, name: o}]
tools:
  - kind: mcp
    connector: dd
    description: "Organisation de production."
`

func TestMCPToolsPassthrough(t *testing.T) {
	tpl, err := Parse([]byte(mcpToolsYAML), "obs.yaml")
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInstance("dd-prod", tpl, map[string]any{"server": "datadog-prod"})
	if err != nil {
		t.Fatal(err)
	}
	if got := in.MCPServers(); len(got) != 1 || got[0] != "datadog-prod" {
		t.Fatalf("serveurs: %v", got)
	}
	if len(in.Tools()) != 0 {
		t.Fatalf("aucun outil statique attendu: %v", in.Tools())
	}
	var calls []string
	var asked []string
	exposed := func(server string) []RemoteTool {
		asked = append(asked, server)
		return []RemoteTool{fakeRemote{"search_logs", &calls}, fakeRemote{"get.metric", &calls}}
	}
	ts := in.MCPTools(exposed)
	if len(asked) != 1 || asked[0] != "datadog-prod" {
		t.Fatalf("serveur demandé: %v", asked)
	}
	var names []string
	for _, tl := range ts {
		names = append(names, tl.Name())
	}
	if !slices.Equal(names, []string{"dd-prod_search_logs", "dd-prod_get_metric"}) {
		t.Fatalf("noms: %v", names)
	}
	if d := ts[0].Description(); !strings.HasPrefix(d, "Organisation de production. [MCP srv] search_logs") {
		t.Fatalf("description: %q", d)
	}
	if !strings.Contains(string(ts[0].Schema()), `"q"`) {
		t.Fatalf("schéma: %s", ts[0].Schema())
	}
	out, err := ts[1].Call(context.Background(), json.RawMessage(`{"q":"x"}`))
	if err != nil || out != "ok get.metric" || len(calls) != 1 || calls[0] != `get.metric {"q":"x"}` {
		t.Fatalf("appel: %q %v %v", out, err, calls)
	}
	if got := in.ToolNames(); !slices.Equal(got, names) {
		t.Fatalf("ToolNames: %v", got)
	}

	if _, err := NewInstance("dd-off", tpl, map[string]any{"server": ""}); err == nil || !strings.Contains(err.Error(), "no tool") {
		t.Fatalf("connecteur désactivé: %v", err)
	}
}

func TestMCPToolsPrefixAndLength(t *testing.T) {
	tpl, err := Parse([]byte(strings.Replace(mcpToolsYAML, "    connector: dd\n", "    connector: dd\n    name: dd\n", 1)), "obs.yaml")
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInstance("p", tpl, map[string]any{"server": "s"})
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	long := strings.Repeat("a", 80)
	ts := in.MCPTools(func(string) []RemoteTool { return []RemoteTool{fakeRemote{"logs", &calls}, fakeRemote{long, &calls}} })
	if len(ts) != 2 || ts[0].Name() != "p_dd_logs" || len(ts[1].Name()) != 64 {
		t.Fatalf("noms: %v %v", ts[0].Name(), len(ts[1].Name()))
	}
}

func TestMCPToolsValidation(t *testing.T) {
	base := "name: x\ntargets: [{kind: a}]\nconnectors: {c: {driver: mcp, server: s}, h: {driver: http, base_url: \"https://x\"}}\n"
	for _, c := range []struct{ tools, want string }{
		{"tools: [{kind: mcp}]", `connector "" is not`},
		{"tools: [{kind: mcp, connector: h}]", `connector "h" is not`},
		{"tools: [{kind: mcp, connector: c}, {kind: mcp, connector: c}]", "already exposed"},
		{"tools: [{kind: inventory, connector: c}]", "only applies to the mcp kind"},
		{"tools: [{kind: mcp, connector: c, name: \"A b\"}]", "is invalid"},
		{"tools: [{kind: nope}]", "mcp"},
	} {
		_, err := Parse([]byte(base+c.tools+"\n"), "x.yaml")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s : %v", c.tools, err)
		}
	}
	if _, err := Parse([]byte(base+"tools: [{kind: mcp, connector: c}, {kind: inventory}]\n"), "x.yaml"); err != nil {
		t.Fatal(err)
	}
}

func TestMCPInlineServer(t *testing.T) {
	y := `name: obs
params:
  site: {type: string, default: example.com}
  key_env: {type: string, default: OBS_KEY}
  app_env: {type: string, default: ""}
connectors:
  api_srv:
    driver: mcp
    url: "https://mcp.{{.site}}/v1/mcp"
    headers:
      X-Key: '{{printf "${%s}" .key_env}}'
      X-App: '{{if .app_env}}{{printf "${%s}" .app_env}}{{end}}'
    allow: [search_*]
    deny: [delete_*]
    timeout: 30s
targets: [{kind: org, name: o}]
tools: [{kind: mcp, connector: api_srv}]
`
	tpl, err := Parse([]byte(y), "obs.yaml")
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInstance("dd-eu", tpl, map[string]any{"site": "datadoghq.eu"})
	if err != nil {
		t.Fatal(err)
	}
	if got := in.MCPServers(); len(got) != 1 || got[0] != "dd-eu-api-srv" {
		t.Fatalf("serveurs: %v", got)
	}
	m, ok := in.MCPInline("dd-eu-api-srv")
	if !ok || m.URL != "https://mcp.datadoghq.eu/v1/mcp" || m.Headers["X-Key"] != "${OBS_KEY}" || len(m.Headers) != 1 || m.Timeout.Duration != 30*time.Second || !slices.Equal(m.Allow, []string{"search_*"}) || !slices.Equal(m.Deny, []string{"delete_*"}) || m.Transport != "http" {
		t.Fatalf("entrée: %+v", m)
	}
	if _, ok := in.MCPInline("autre"); ok {
		t.Fatal("entrée inconnue trouvée")
	}
	for _, c := range []struct{ conn, want string }{
		{"{driver: mcp, server: s, url: \"https://x\"}", "exclusive"},
		{"{driver: mcp, server: s, allow: [a]}", "only applies with url"},
		{"{driver: mcp, url: \"https://x\", timeout: nope}", "invalid duration"},
		{"{driver: mcp}", "or url is required"},
	} {
		tpl, err := Parse([]byte("name: x\ntargets: [{kind: a}]\ntools: [{kind: mcp, connector: c}]\nconnectors: {c: "+c.conn+"}\n"), "x.yaml")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewInstance("i", tpl, nil); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s : %v", c.conn, err)
		}
	}
}

func TestTemplateMinVersion(t *testing.T) {
	old := config.Version
	t.Cleanup(func() { config.Version = old })
	config.Version = "0.71.1"
	_, err := Parse([]byte("name: x\nmin_version: 0.72.0\ntargets: [{kind: a}]\ntools: [{kind: inventory, futur: 1}]\n"), "x.yaml")
	if err == nil || !strings.Contains(err.Error(), "template x.yaml") || !strings.Contains(err.Error(), ">= 0.72.0") {
		t.Fatalf("%v", err)
	}
	config.Version = "0.72.0"
	if _, err := Parse([]byte("name: x\nmin_version: 0.72.0\ntargets: [{kind: a}]\ntools: [{kind: inventory}]\n"), "x.yaml"); err != nil {
		t.Fatal(err)
	}
}
