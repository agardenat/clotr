package mcp

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agardenat/clotr/internal/config"
)

var objSchema = map[string]any{"type": "object", "properties": map[string]any{"q": map[string]any{"type": "string"}}}

func handler(text string, isErr bool) sdk.ToolHandler {
	return func(_ context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		var args map[string]any
		_ = json.Unmarshal(req.Params.Arguments, &args)
		return &sdk.CallToolResult{IsError: isErr, Content: []sdk.Content{&sdk.TextContent{Text: text + ":" + toString(args["q"])}}}, nil
	}
}

func toString(v any) string {
	s, _ := v.(string)
	return s
}

func TestFilteringAndCall(t *testing.T) {
	ctx := context.Background()
	srv := sdk.NewServer(&sdk.Implementation{Name: "test", Version: "1"}, nil)
	ro := &sdk.ToolAnnotations{ReadOnlyHint: true}
	srv.AddTool(&sdk.Tool{Name: "query", InputSchema: objSchema, Annotations: ro}, handler("ok", false))
	srv.AddTool(&sdk.Tool{Name: "delete_thing", InputSchema: objSchema}, handler("deleted", false))
	srv.AddTool(&sdk.Tool{Name: "search", InputSchema: objSchema}, handler("found", false))
	srv.AddTool(&sdk.Tool{Name: "get_secret", InputSchema: objSchema, Annotations: ro}, handler("s", false))
	srv.AddTool(&sdk.Tool{Name: "broken", InputSchema: objSchema, Annotations: ro}, handler("boom", true))
	st, ct := sdk.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cfg := config.MCPServer{Name: "srv", Allow: []string{"search"}, Deny: []string{"*secret*"}, Timeout: config.Duration{Duration: 5 * time.Second}}
	s, err := ConnectTransport(ctx, cfg, ct, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var names []string
	for _, tl := range s.Tools() {
		names = append(names, tl.Name())
	}
	slices.Sort(names)
	if strings.Join(names, ",") != "mcp_srv_broken,mcp_srv_query,mcp_srv_search" {
		t.Fatalf("outils exposés: %v", names)
	}
	slices.Sort(s.Skipped())
	if strings.Join(s.Skipped(), ",") != "delete_thing,get_secret" {
		t.Fatalf("outils écartés: %v", s.Skipped())
	}
	for _, tl := range s.Tools() {
		out, err := tl.Call(ctx, json.RawMessage(`{"q":"x"}`))
		switch tl.Name() {
		case "mcp_srv_query":
			if err != nil || strings.TrimSpace(out) != "ok:x" {
				t.Errorf("query: %q %v", out, err)
			}
		case "mcp_srv_broken":
			if err == nil || !strings.Contains(err.Error(), "boom") {
				t.Errorf("broken: %q %v", out, err)
			}
		}
	}
}

func TestToolName(t *testing.T) {
	if got := ToolName("srv", "a.b/c"); got != "mcp_srv_a_b_c" {
		t.Errorf("nom: %s", got)
	}
	if got := ToolName("srv", strings.Repeat("x", 100)); len(got) != 64 {
		t.Errorf("longueur: %d", len(got))
	}
}
