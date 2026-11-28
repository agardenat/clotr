package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/llm"
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

func TestConnectWriter(t *testing.T) {
	ctx := context.Background()
	srv := sdk.NewServer(&sdk.Implementation{Name: "test", Version: "1"}, nil)
	srv.AddTool(&sdk.Tool{Name: "create_doc", InputSchema: objSchema}, handler("created", false))
	srv.AddTool(&sdk.Tool{Name: "delete_doc", InputSchema: objSchema}, handler("deleted", false))
	st, ct := sdk.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cfg := config.MCPServer{Name: "docs", Deny: []string{"delete_*"}, Timeout: config.Duration{Duration: 5 * time.Second}}
	s, err := ConnectWriterTransport(ctx, cfg, ct, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(s.Tools()) != 1 || s.Tools()[0].Name() != "mcp_docs_create_doc" {
		t.Fatalf("outils exposés: %v", s.Tools())
	}
}

func TestFetch(t *testing.T) {
	ctx := context.Background()
	own := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/files/report.docx":
			if r.Header.Get("Authorization") != "Bearer k" {
				http.Error(w, "no auth", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte("PKdata"))
		case "/big":
			_, _ = w.Write(make([]byte, 2048))
		default:
			http.NotFound(w, r)
		}
	}))
	defer own.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("requête vers un autre hôte en http: %s", r.URL)
	}))
	defer other.Close()
	s := &Server{cfg: config.MCPServer{Name: "docs", URL: own.URL + "/mcp", Headers: map[string]string{"Authorization": "Bearer k"}}}
	data, err := s.Fetch(ctx, own.URL+"/files/report.docx?sig=1", 1024)
	if err != nil || string(data) != "PKdata" {
		t.Fatalf("même origine: %q %v", data, err)
	}
	if _, err := s.Fetch(ctx, own.URL+"/absent", 1024); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("404: %v", err)
	}
	if _, err := s.Fetch(ctx, own.URL+"/big", 1024); err == nil {
		t.Fatal("taille maximale ignorée")
	}
	if _, err := s.Fetch(ctx, other.URL+"/x.docx", 1024); err == nil {
		t.Fatal("http vers un autre hôte accepté")
	}
	if _, err := s.Fetch(ctx, "file:///etc/passwd", 1024); err == nil {
		t.Fatal("file:// accepté")
	}
}

func TestCallExposedOnlyReadTools(t *testing.T) {
	ctx := context.Background()
	srv := sdk.NewServer(&sdk.Implementation{Name: "test", Version: "1"}, nil)
	srv.AddTool(&sdk.Tool{Name: "query", InputSchema: objSchema, Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}}, handler("ok", false))
	srv.AddTool(&sdk.Tool{Name: "add_commit", InputSchema: objSchema}, handler("written", false))
	st, ct := sdk.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	s, err := ConnectTransport(ctx, config.MCPServer{Name: "gl", Timeout: config.Duration{Duration: 5 * time.Second}}, ct, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, _, _, err := s.CallExposed(ctx, "add_commit", map[string]any{"q": "x"}); err == nil || !strings.Contains(err.Error(), "not exposed") {
		t.Fatalf("outil d'écriture accepté: %v", err)
	}
	text, _, isErr, err := s.CallExposed(ctx, "query", map[string]any{"q": "x"})
	if err != nil || isErr || text != "ok:x" {
		t.Fatalf("lecture: %q %v %v", text, isErr, err)
	}
}

func TestRateLimitedCallRetried(t *testing.T) {
	ctx := context.Background()
	srv := sdk.NewServer(&sdk.Implementation{Name: "test", Version: "1"}, nil)
	calls := 0
	srv.AddTool(&sdk.Tool{Name: "report", InputSchema: objSchema, Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, _ *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			calls++
			if calls == 1 {
				reset := time.Now().UTC().Add(time.Second).Format("2006-01-02 15:04:05")
				return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: "Error: Rate limit exceeded. Limit resets at: " + reset + " UTC"}}}, nil
			}
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "done"}}}, nil
		})
	st, ct := sdk.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	saved := GateFor
	GateFor = func(config.MCPServer) *llm.Gate { return llm.NewGate(0) }
	defer func() { GateFor = saved }()
	s, err := ConnectTransport(ctx, config.MCPServer{Name: "gw", Timeout: config.Duration{Duration: 5 * time.Second}}, ct, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	text, _, isErr, err := s.CallExposed(ctx, "report", nil)
	if err != nil || isErr || text != "done" || calls != 2 {
		t.Fatalf("text=%q isErr=%v err=%v calls=%d", text, isErr, err, calls)
	}
}

func TestNoGateNoRetry(t *testing.T) {
	ctx := context.Background()
	srv := sdk.NewServer(&sdk.Implementation{Name: "test", Version: "1"}, nil)
	calls := 0
	srv.AddTool(&sdk.Tool{Name: "report", InputSchema: objSchema, Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, _ *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			calls++
			return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: "Rate limit exceeded"}}}, nil
		})
	st, ct := sdk.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	saved := GateFor
	GateFor = nil
	defer func() { GateFor = saved }()
	s, err := ConnectTransport(ctx, config.MCPServer{Name: "other", Timeout: config.Duration{Duration: 5 * time.Second}}, ct, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, _, isErr, _ := s.CallExposed(ctx, "report", nil); !isErr || calls != 1 {
		t.Fatalf("isErr=%v calls=%d", isErr, calls)
	}
}
