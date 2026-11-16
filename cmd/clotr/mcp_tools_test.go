package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/template"
	"github.com/agardenat/clotr/internal/tools"
	"github.com/agardenat/clotr/internal/tools/mcp"
)

func TestTemplateMCPToolsRegistered(t *testing.T) {
	ctx := context.Background()
	srv := sdk.NewServer(&sdk.Implementation{Name: "obs", Version: "1"}, nil)
	schema := map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "string"}}}
	srv.AddTool(&sdk.Tool{Name: "search_logs", Description: "cherche des logs", InputSchema: schema, Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}}, func(_ context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		var args map[string]any
		_ = json.Unmarshal(req.Params.Arguments, &args)
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "logs:" + args["query"].(string)}}}, nil
	})
	srv.AddTool(&sdk.Tool{Name: "delete_monitor", InputSchema: schema}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "deleted"}}}, nil
	})
	st, ct := sdk.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	off := false
	s, err := mcp.ConnectTransport(ctx, config.MCPServer{Name: "obs-prod", Enabled: &off, Timeout: config.Duration{Duration: 5 * time.Second}}, ct, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	dir := t.TempDir()
	yaml := "name: obs\ndescription: observabilité\nparams:\n  mcp: {type: string, default: \"\"}\nconnectors:\n  srv: {driver: mcp, server: \"{{.mcp}}\"}\ntargets: [{kind: org, name: prod}]\ntools:\n  - {kind: mcp, connector: srv}\n"
	if err := os.WriteFile(filepath.Join(dir, "obs.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := template.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	tpl, _ := set.Get("obs")
	in, err := template.NewInstance("dd", tpl, map[string]any{"mcp": "obs-prod"})
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Defer(ctx, "", time.Hour, false); err != nil {
		t.Fatal(err)
	}
	rt := &app{cfg: &config.Config{}, registry: tools.NewRegistry(100), audit: audit.Nop(), instances: []*template.Instance{in}, mcpServers: []*mcp.Server{s}, instanceEnv: map[string][]string{"dd": in.EnvironmentLines()}}
	rt.registry.Add(in.Tools()...)
	rt.registry.AddGroup(in.ToolPrefix())
	var warns []string
	rt.connectTemplateMCP(ctx, func(w string) { warns = append(warns, w) })
	if len(warns) > 0 {
		t.Fatalf("avertissements: %v", warns)
	}
	if got := rt.registry.Names(); !slices.Equal(got, []string{"dd_search_logs"}) {
		t.Fatalf("outils: %v", got)
	}
	if env := strings.Join(rt.instanceEnv["dd"], "\n"); !strings.Contains(env, "Outils : dd_search_logs") {
		t.Fatalf("environnement: %s", env)
	}
	out, err := rt.registry.Call(ctx, []string{"dd_search_logs"}, "dd_search_logs", `{"query":"status:error"}`)
	if err != nil || strings.TrimSpace(out) != "logs:status:error" {
		t.Fatalf("appel: %q %v", out, err)
	}
	if !in.Activated() {
		t.Fatal("l'appel doit activer l'instance")
	}
	if reg, _ := rt.scope([]string{"dd"}, "erreurs de la nuit"); !slices.Equal(reg.Names(), []string{"dd_search_logs"}) {
		t.Fatalf("-t dd: %v", reg.Names())
	}

	in2, err := template.NewInstance("dd2", tpl, map[string]any{"mcp": "absent"})
	if err != nil {
		t.Fatal(err)
	}
	rt.instances = []*template.Instance{in2}
	rt.instanceEnv["dd2"] = in2.EnvironmentLines()
	rt.connectTemplateMCP(ctx, func(w string) { warns = append(warns, w) })
	if _, ok := rt.instanceEnv["dd2"]; ok || len(warns) != 1 || !strings.Contains(warns[0], "absent") {
		t.Fatalf("instance sans serveur: %v %v", rt.instanceEnv["dd2"], warns)
	}
}

func TestTemplateMCPInlineServer(t *testing.T) {
	ctx := context.Background()
	srv := sdk.NewServer(&sdk.Implementation{Name: "obs", Version: "1"}, nil)
	schema := map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "string"}}}
	srv.AddTool(&sdk.Tool{Name: "search_logs", InputSchema: schema}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "trouvé"}}}, nil
	})
	srv.AddTool(&sdk.Tool{Name: "delete_logs", InputSchema: schema}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "supprimé"}}}, nil
	})
	h := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return srv }, nil)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Key") != "secret-1" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	}))
	defer hs.Close()
	t.Setenv("OBS_TEST_KEY", "secret-1")
	dir := t.TempDir()
	yaml := "name: obs\nparams:\n  url: {type: string, default: \"\"}\nconnectors:\n  srv:\n    driver: mcp\n    url: \"{{.url}}\"\n    headers: {X-Key: \"${OBS_TEST_KEY}\"}\n    allow: [search_*]\ntargets: [{kind: org, name: prod}]\ntools:\n  - {kind: mcp, connector: srv}\n"
	if err := os.WriteFile(filepath.Join(dir, "obs.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := template.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	tpl, _ := set.Get("obs")
	in, err := template.NewInstance("dd", tpl, map[string]any{"url": hs.URL})
	if err != nil {
		t.Fatal(err)
	}
	rt := &app{cfg: &config.Config{}, registry: tools.NewRegistry(100), audit: audit.Nop(), instances: []*template.Instance{in}, instanceEnv: map[string][]string{}}
	var warns []string
	rt.connectTemplateMCP(ctx, func(w string) { warns = append(warns, w) })
	defer rt.close()
	if len(warns) > 0 {
		t.Fatalf("avertissements: %v", warns)
	}
	if got := rt.registry.Names(); !slices.Equal(got, []string{"dd_search_logs"}) {
		t.Fatalf("outils: %v", got)
	}
	out, err := rt.registry.Call(ctx, []string{"dd_search_logs"}, "dd_search_logs", `{"query":"x"}`)
	if err != nil || strings.TrimSpace(out) != "trouvé" {
		t.Fatalf("appel: %q %v", out, err)
	}
}
