package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agardenat/clotr/internal/config"
)

func TestMessageDecoding(t *testing.T) {
	var m Message
	if err := json.Unmarshal([]byte(`{"role":"assistant","content":null,"tool_calls":[{"id":"1","type":"function","function":{"name":"x","arguments":{"a":1}}}]}`), &m); err != nil {
		t.Fatal(err)
	}
	if m.Content != "" || m.ToolCalls[0].Function.Arguments != `{"a":1}` {
		t.Fatalf("%+v", m)
	}
	if err := json.Unmarshal([]byte(`{"role":"assistant","content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]}`), &m); err != nil || m.Content != "ab" {
		t.Fatalf("parts: %q %v", m.Content, err)
	}
}

func TestClientAndErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req.Model {
		case "ok":
			if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer k" {
				w.WriteHeader(400)
				return
			}
			w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"prompt_tokens":3}}`))
		case "busy":
			w.WriteHeader(429)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	t.Setenv("K", "k")
	cfg, _ := config.Parse([]byte("providers:\n  - {name: p, base_url: " + srv.URL + "/v1, api_key_env: K, max_concurrency: 1}\n"))
	pool := NewPool(cfg, srv.Client())
	resp, err := pool.Chat(context.Background(), "p", Request{Model: "ok"})
	if err != nil || resp.Choices[0].Message.Content != "hi" || resp.Usage.PromptTokens != 3 {
		t.Fatalf("%+v %v", resp, err)
	}
	_, err = pool.Chat(context.Background(), "p", Request{Model: "busy"})
	if !Transient(err) || !Failover(err) {
		t.Fatalf("429: %v", err)
	}
	_, err = pool.Chat(context.Background(), "p", Request{Model: "missing"})
	if Transient(err) || !Failover(err) {
		t.Fatalf("404: %v", err)
	}
	if Failover(&APIError{Status: 401}) || Failover(errors.New("x")) {
		t.Fatal("401 ne doit pas basculer")
	}
}

func TestQuota(t *testing.T) {
	q := &APIError{Status: 429, Body: `{"error":"INSUFFICIENT QUOTA"}`}
	if !Transient(q) || !Failover(q) || Unavailable(q) {
		t.Fatal("429 quota: temporaire, retry puis bascule, jamais écarté")
	}
	b := &APIError{Status: 403, Body: "Budget has been exceeded"}
	if Transient(b) || !Failover(b) || Unavailable(b) {
		t.Fatal("403 budget: bascule directe sans écartement")
	}
	if !Unavailable(&APIError{Status: 404}) {
		t.Fatal("404: modèle écarté")
	}
	if parseRetryAfter("7") != 7*time.Second || parseRetryAfter("") != 0 {
		t.Fatal("Retry-After")
	}
}

func TestCostHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-litellm-response-cost", "3.63e-05")
		w.Header().Set("x-litellm-key-spend", "0.1518")
		w.Header().Set("x-litellm-key-max-budget", "50.0")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"x"}}]}`))
	}))
	defer srv.Close()
	cfg, _ := config.Parse([]byte("providers:\n  - {name: p, base_url: " + srv.URL + "}\n"))
	resp, err := NewPool(cfg, srv.Client()).Chat(context.Background(), "p", Request{Model: "m"})
	if err != nil || resp.Cost.Response != 3.63e-05 || !resp.Cost.HasKey || resp.Cost.KeyMax != 50 {
		t.Fatalf("%+v %v", resp.Cost, err)
	}
}

func TestUserAgentAndSession(t *testing.T) {
	var ua, sess string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua, sess = r.Header.Get("User-Agent"), r.Header.Get("x-opencode-session")
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"x"}}]}`))
	}))
	defer srv.Close()
	cfg, _ := config.Parse([]byte("providers:\n  - {name: p, base_url: " + srv.URL + ", session_header: x-opencode-session}\n  - {name: q, base_url: " + srv.URL + "}\n"))
	pool := NewPool(cfg, srv.Client())
	if _, err := pool.Chat(context.Background(), "p", Request{Model: "m", Session: "s1"}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ua, "clotr/") || sess != "s1" {
		t.Fatalf("ua=%q session=%q", ua, sess)
	}
	_, _ = pool.Chat(context.Background(), "q", Request{Model: "m", Session: "s2"})
	if sess != "" {
		t.Fatalf("session envoyée sans session_header: %q", sess)
	}
}

func sse(w http.ResponseWriter, chunks ...string) {
	w.Header().Set("Content-Type", "text/event-stream")
	f := w.(http.Flusher)
	for _, c := range chunks {
		fmt.Fprintf(w, "data: %s\n\n", c)
		f.Flush()
	}
}

func TestStream(t *testing.T) {
	var gotStream bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotStream = req["stream"] == true && req["stream_options"] != nil
		sse(w,
			`{"choices":[{"delta":{"role":"assistant","reasoning_content":"je réfléchis"}}]}`,
			`{"choices":[{"delta":{"content":"Voici "}}]}`,
			`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","type":"function","function":{"name":"k8s_list","arguments":"{\"reso"}}]}}]}`,
			`{"choices":[{"delta":{"tool_calls":[{"index":1,"id":"c2","function":{"name":"k8s_get","arguments":{"name":"x"}}}]}}]}`,
			`{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"urce\":\"pods\"}"}}]}}]}`,
			`{"choices":[{"delta":{"content":"le plan"},"finish_reason":"tool_calls"}]}`,
			`{"choices":[],"usage":{"prompt_tokens":12,"completion_tokens":7}}`,
			`[DONE]`)
	}))
	defer srv.Close()
	cfg, _ := config.Parse([]byte("providers:\n  - {name: p, base_url: " + srv.URL + "}\n"))
	var calls []StreamProgress
	var deltas []string
	resp, err := NewPool(cfg, srv.Client()).Chat(context.Background(), "p", Request{Model: "m", OnProgress: func(p StreamProgress) { calls = append(calls, p) }, OnContent: func(d string) { deltas = append(deltas, d) }})
	if err != nil {
		t.Fatal(err)
	}
	m := resp.Choices[0].Message
	if !gotStream || m.Content != "Voici le plan" || len(m.ToolCalls) != 2 || resp.Choices[0].FinishReason != "tool_calls" {
		t.Fatalf("%+v stream=%v", resp, gotStream)
	}
	if m.ToolCalls[0].ID != "c1" || m.ToolCalls[0].Function.Arguments != `{"resource":"pods"}` || m.ToolCalls[1].Function.Arguments != `{"name":"x"}` {
		t.Fatalf("tool calls: %+v", m.ToolCalls)
	}
	if resp.Usage.CompletionTokens != 7 || resp.Cost.Reported {
		t.Fatalf("usage/cost: %+v %+v", resp.Usage, resp.Cost)
	}
	if strings.Join(deltas, "|") != "Voici |le plan" {
		t.Fatalf("texte en direct: %q", deltas)
	}
	if len(calls) != 7 || calls[len(calls)-1].ToolCalls != 2 || calls[0].ReasoningChars == 0 {
		t.Fatalf("progression: %+v", calls)
	}
}

func TestStreamIdleAndErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req["model"] {
		case "stall":
			sse(w, `{"choices":[{"delta":{"content":"a"}}]}`)
			time.Sleep(500 * time.Millisecond)
		case "err":
			sse(w, `{"error":{"message":"upstream exploded"}}`)
		case "empty":
			sse(w, `[DONE]`)
		}
	}))
	defer srv.Close()
	cfg, _ := config.Parse([]byte("providers:\n  - {name: p, base_url: " + srv.URL + "}\nlimits: {idle_timeout: 100ms}\n"))
	pool := NewPool(cfg, srv.Client())
	t0 := time.Now()
	_, err := pool.Chat(context.Background(), "p", Request{Model: "stall"})
	if err == nil || !Transient(err) || !strings.Contains(err.Error(), "aucune donnée") || time.Since(t0) > 400*time.Millisecond {
		t.Fatalf("idle: %v en %v", err, time.Since(t0))
	}
	if _, err := pool.Chat(context.Background(), "p", Request{Model: "err"}); err == nil || !Transient(err) || !strings.Contains(err.Error(), "exploded") {
		t.Fatalf("erreur de flux: %v", err)
	}
	if _, err := pool.Chat(context.Background(), "p", Request{Model: "empty"}); err == nil {
		t.Fatal("flux vide accepté")
	}
}

func TestRequestTimeoutFailsOver(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for range 10 {
			sse(w, `{"choices":[{"delta":{"content":"a"}}]}`)
			time.Sleep(50 * time.Millisecond)
		}
	}))
	defer srv.Close()
	cfg, _ := config.Parse([]byte("providers:\n  - {name: p, base_url: " + srv.URL + "}\nlimits: {request_timeout: 150ms, idle_timeout: 1s}\n"))
	pool := NewPool(cfg, srv.Client())
	_, err := pool.Chat(context.Background(), "p", Request{Model: "slow"})
	if !errors.Is(err, ErrRequestTimeout) || Transient(err) || !Failover(err) {
		t.Fatalf("request_timeout: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := pool.Chat(ctx, "p", Request{Model: "slow"}); errors.Is(err, ErrRequestTimeout) {
		t.Fatalf("délai de l'appelant pris pour request_timeout: %v", err)
	}
}

func TestStreamDisabled(t *testing.T) {
	var gotStream any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotStream = req["stream"]
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"x"}}]}`))
	}))
	defer srv.Close()
	cfg, _ := config.Parse([]byte("providers:\n  - {name: p, base_url: " + srv.URL + ", stream: false}\n"))
	if _, err := NewPool(cfg, srv.Client()).Chat(context.Background(), "p", Request{Model: "m"}); err != nil || gotStream != nil {
		t.Fatalf("stream=%v err=%v", gotStream, err)
	}
}

func TestStreamResetIsTransient(t *testing.T) {
	err := errors.New("stream error: stream ID 341; INTERNAL_ERROR; received from peer")
	if !Transient(err) || !Failover(err) {
		t.Fatal("reset de flux HTTP/2 non traité comme temporaire")
	}
	if Transient(errors.New("x509: certificate signed by unknown authority")) {
		t.Fatal("erreur TLS traitée comme temporaire")
	}
}
