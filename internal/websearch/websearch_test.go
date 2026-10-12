package websearch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agardenat/clotr/internal/config"
)

func TestMessages(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/messages" {
			t.Errorf("chemin %s", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "k" || r.Header.Get("Authorization") != "" {
			t.Errorf("authentification: %v", r.Header)
		}
		if r.Header.Get("anthropic-version") == "" || r.Header.Get("x-session") == "" {
			t.Errorf("en-têtes: %v", r.Header)
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Model    string           `json:"model"`
			Messages []map[string]any `json:"messages"`
			Tools    []map[string]any `json:"tools"`
		}
		_ = json.Unmarshal(body, &req)
		if req.Model != "haiku" || req.Tools[0]["type"] != "web_search_20250305" {
			t.Errorf("requête: %s", body)
		}
		if calls == 1 {
			if len(req.Messages) != 1 {
				t.Errorf("messages: %d", len(req.Messages))
			}
			_, _ = io.WriteString(w, `{"stop_reason":"pause_turn","content":[{"type":"server_tool_use","id":"s1","name":"web_search","input":{"query":"go latest release"}},{"type":"web_search_tool_result","tool_use_id":"s1","content":[{"type":"web_search_result","url":"https://go.dev/doc/devel/release","title":"Release History"}]}],"usage":{"input_tokens":100,"output_tokens":10,"server_tool_use":{"web_search_requests":1}}}`)
			return
		}
		if len(req.Messages) != 2 || req.Messages[1]["role"] != "assistant" {
			t.Errorf("reprise après pause_turn: %s", body)
		}
		_, _ = io.WriteString(w, `{"stop_reason":"end_turn","content":[{"type":"text","text":"Go 1.27.2, publiée le 8 octobre 2026.","citations":[{"type":"web_search_result_location","url":"https://go.dev/doc/devel/release","title":"Release History"},{"type":"web_search_result_location","url":"https://go.dev/doc/devel/release","title":"Release History"}]}],"usage":{"input_tokens":200,"output_tokens":20}}`)
	}))
	defer srv.Close()
	tool, err := New(config.Provider{Name: "go", BaseURL: srv.URL + "/v1", Key: "k", SessionHeader: "x-session"}, "haiku", "messages", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	out, err := tool.Call(context.Background(), json.RawMessage(`{"query":"dernière version de Go"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Go 1.27.2", "- Release History — https://go.dev/doc/devel/release", "Requêtes : go latest release", "go/haiku, 1 recherche(s), 300 tokens en entrée, 30 en sortie"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q absent de:\n%s", want, out)
		}
	}
	if strings.Count(out, "https://go.dev/doc/devel/release") != 1 {
		t.Errorf("source dupliquée:\n%s", out)
	}
}

func TestResponses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("requête: %s %v", r.URL.Path, r.Header)
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"tools":[{"type":"web_search"}]`) {
			t.Errorf("outil absent: %s", body)
		}
		_, _ = io.WriteString(w, `{"status":"completed","output":[{"type":"web_search_call","action":{"type":"search","query":"go release"}},{"type":"reasoning"},{"type":"web_search_call","action":{"type":"open_page"}},{"type":"message","content":[{"type":"output_text","text":"Go 1.27.2. Voir aussi ([go.dev](https://go.dev/doc/devel/release)), https://go.dev/dl/.","annotations":[{"type":"url_citation","url":"https://go.dev/dl/","title":"Downloads"}]}]}],"usage":{"input_tokens":50,"output_tokens":5}}`)
	}))
	defer srv.Close()
	tool, _ := New(config.Provider{Name: "go", BaseURL: srv.URL + "/v1/", Key: "k"}, "luna", "responses", time.Minute)
	out, err := tool.Call(context.Background(), json.RawMessage(`{"query":"version de Go"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Go 1.27.2.", "- Downloads — https://go.dev/dl/\n- https://go.dev/doc/devel/release\n", "Requêtes : go release\n", "2 recherche(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q absent de:\n%s", want, out)
		}
	}
}

func TestErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/responses") {
			_, _ = io.WriteString(w, `{"status":"incomplete","output":[{"type":"reasoning"}]}`)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"message":"Model does not support this protocol."}}`)
	}))
	defer srv.Close()
	p := config.Provider{Name: "go", BaseURL: srv.URL}
	if _, err := New(p, "m", "chat", time.Minute); err == nil {
		t.Error("api invalide acceptée")
	}
	m, _ := New(p, "m", "messages", time.Minute)
	if _, err := m.Call(context.Background(), json.RawMessage(`{"query":"q"}`)); err == nil || !strings.Contains(err.Error(), "HTTP 400") || !strings.Contains(err.Error(), "protocol") {
		t.Errorf("erreur HTTP: %v", err)
	}
	if _, err := m.Call(context.Background(), json.RawMessage(`{"query":" "}`)); err == nil {
		t.Error("query vide acceptée")
	}
	r, _ := New(p, "m", "responses", time.Minute)
	if _, err := r.Call(context.Background(), json.RawMessage(`{"query":"q"}`)); err == nil {
		t.Error("réponse sans texte acceptée")
	}
}
