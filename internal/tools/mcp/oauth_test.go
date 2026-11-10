package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agardenat/clotr/internal/browser"
	"github.com/agardenat/clotr/internal/config"
)

type fakeAS struct {
	mu         sync.Mutex
	base       string
	registered int
	browsed    int
	refreshed  int
	challenge  string
	redirect   string
	valid      map[string]bool
	refresh    string
	n          int
	denyGrant  bool
}

func (f *fakeAS) issue() map[string]any {
	f.n++
	at := fmt.Sprintf("at-%d", f.n)
	f.valid[at] = true
	f.refresh = fmt.Sprintf("rt-%d", f.n)
	return map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": 3600, "refresh_token": f.refresh, "scope": "mcp"}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func newFakeGitLab(t *testing.T) (*fakeAS, *httptest.Server) {
	t.Helper()
	f := &fakeAS{valid: map[string]bool{}}
	srv := sdk.NewServer(&sdk.Implementation{Name: "gl", Version: "1"}, nil)
	srv.AddTool(&sdk.Tool{Name: "get_issue", InputSchema: objSchema, Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}}, handler("issue", false))
	mcpHandler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return srv }, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/api/v4/mcp", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"resource": f.base + "/api/v4/mcp", "authorization_servers": []string{f.base}, "scopes_supported": []string{"mcp"}})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"issuer": f.base, "authorization_endpoint": f.base + "/oauth/authorize", "token_endpoint": f.base + "/oauth/token",
			"registration_endpoint": f.base + "/oauth/register", "scopes_supported": []string{"mcp", "api"},
			"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		})
	})
	mux.HandleFunc("/oauth/register", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		f.mu.Lock()
		f.registered++
		f.mu.Unlock()
		writeJSON(w, 201, map[string]any{"client_id": "cid", "redirect_uris": m["redirect_uris"], "token_endpoint_auth_method": "none"})
	})
	mux.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != "cid" || q.Get("code_challenge_method") != "S256" || q.Get("scope") != "mcp" {
			http.Error(w, "bad authorize "+r.URL.RawQuery, 400)
			return
		}
		f.mu.Lock()
		f.challenge = q.Get("code_challenge")
		f.redirect = q.Get("redirect_uri")
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=c1&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("code") != "c1" || base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge || r.Form.Get("redirect_uri") != f.redirect {
				writeJSON(w, 400, map[string]any{"error": "invalid_grant"})
				return
			}
			writeJSON(w, 200, f.issue())
		case "refresh_token":
			if f.denyGrant || r.Form.Get("refresh_token") != f.refresh {
				writeJSON(w, 400, map[string]any{"error": "invalid_grant"})
				return
			}
			f.refreshed++
			writeJSON(w, 200, f.issue())
		default:
			writeJSON(w, 400, map[string]any{"error": "unsupported_grant_type"})
		}
	})
	mux.HandleFunc("/api/v4/mcp", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		f.mu.Lock()
		ok := f.valid[tok]
		f.mu.Unlock()
		if !ok {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="GitLab", scope="mcp", resource_metadata="%s/.well-known/oauth-protected-resource/api/v4/mcp"`, f.base))
			writeJSON(w, 401, map[string]any{"message": "401 Unauthorized"})
			return
		}
		mcpHandler.ServeHTTP(w, r)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	f.base = ts.URL
	return f, ts
}

func fakeBrowser(t *testing.T, f *fakeAS) {
	t.Helper()
	prev := browser.Open
	browser.Open = func(u string) {
		f.mu.Lock()
		f.browsed++
		f.mu.Unlock()
		go func() {
			resp, err := http.Get(u)
			if err != nil {
				t.Errorf("navigateur: %v", err)
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || !strings.Contains(string(body), "clotr") {
				t.Errorf("page de retour %d: %s", resp.StatusCode, body)
			}
		}()
	}
	t.Cleanup(func() { browser.Open = prev })
}

func connectOnce(t *testing.T, cfg config.MCPServer) {
	t.Helper()
	s, err := Connect(context.Background(), cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(s.Tools()) != 1 || s.Tools()[0].Name() != "mcp_gitlab_get_issue" {
		t.Fatalf("outils: %d", len(s.Tools()))
	}
	out, err := s.Tools()[0].Call(context.Background(), json.RawMessage(`{"q":"42"}`))
	if err != nil || !strings.Contains(out, "issue:42") {
		t.Fatalf("appel: %q %v", out, err)
	}
}

func (f *fakeAS) counts() (int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.registered, f.browsed, f.refreshed
}

func TestOAuthLoginCacheRefreshRelogin(t *testing.T) {
	dir := t.TempDir()
	prevDir := oauthDir
	oauthDir = func() string { return dir }
	t.Cleanup(func() { oauthDir = prevDir })
	f, ts := newFakeGitLab(t)
	fakeBrowser(t, f)
	cfg := config.MCPServer{Name: "gitlab", URL: ts.URL + "/api/v4/mcp", Transport: "http", Auth: config.MCPAuthOAuth, Timeout: config.Duration{Duration: 10 * time.Second}}

	connectOnce(t, cfg)
	if r, b, _ := f.counts(); r != 1 || b != 1 {
		t.Fatalf("premier login: enregistrements=%d navigateur=%d", r, b)
	}
	path := filepath.Join(dir, "gitlab.json")
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("cache: %v %v", st, err)
	}

	connectOnce(t, cfg)
	if r, b, rf := f.counts(); r != 1 || b != 1 || rf != 0 {
		t.Fatalf("jeton en cache: enregistrements=%d navigateur=%d refresh=%d", r, b, rf)
	}

	var c oauthCache
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	c.Token.Expiry = time.Now().Add(-time.Hour)
	b, _ = json.Marshal(c)
	_ = os.WriteFile(path, b, 0o600)
	connectOnce(t, cfg)
	if r, b, rf := f.counts(); r != 1 || b != 1 || rf != 1 {
		t.Fatalf("refresh: enregistrements=%d navigateur=%d refresh=%d", r, b, rf)
	}

	b, _ = os.ReadFile(path)
	_ = json.Unmarshal(b, &c)
	c.Token.Expiry = time.Now().Add(-time.Hour)
	b, _ = json.Marshal(c)
	_ = os.WriteFile(path, b, 0o600)
	f.mu.Lock()
	f.denyGrant = true
	f.mu.Unlock()
	connectOnce(t, cfg)
	if r, b, _ := f.counts(); r != 1 || b != 2 {
		t.Fatalf("refresh refusé: enregistrements=%d navigateur=%d", r, b)
	}

	b, _ = os.ReadFile(path)
	_ = json.Unmarshal(b, &c)
	c.Token.Expiry = time.Now().Add(-time.Hour)
	b, _ = json.Marshal(c)
	_ = os.WriteFile(path, b, 0o600)
	CloseLogins()
	t.Cleanup(func() { loginsClosed.Store(false) })
	if _, err := Connect(context.Background(), cfg, "test"); err == nil || !strings.Contains(err.Error(), "start clotr again") {
		t.Fatalf("connexion en cours de run: %v", err)
	}
	if _, b, _ := f.counts(); b != 2 {
		t.Fatalf("navigateur ouvert en cours de run: %d", b)
	}
}

func TestOAuthCacheIgnoredForOtherURL(t *testing.T) {
	dir := t.TempDir()
	prevDir := oauthDir
	oauthDir = func() string { return dir }
	t.Cleanup(func() { oauthDir = prevDir })
	b, _ := json.Marshal(oauthCache{URL: "https://ailleurs/mcp", ClientID: "x", RedirectURL: "http://127.0.0.1:1/callback"})
	_ = os.WriteFile(filepath.Join(dir, "gitlab.json"), b, 0o600)
	s := loadStore("gitlab", "https://git.example/api/v4/mcp")
	if s.data.ClientID != "" || s.data.URL != "https://git.example/api/v4/mcp" {
		t.Fatalf("cache d'une autre URL repris: %+v", s.data)
	}
}

func TestStretchExtendsAndRestores(t *testing.T) {
	ctx, cancel := withStretch(context.Background(), 50*time.Millisecond)
	defer cancel()
	restore := stretch(ctx, time.Hour)
	time.Sleep(120 * time.Millisecond)
	if ctx.Err() != nil {
		t.Fatal("contexte expiré pendant l'attente du navigateur")
	}
	restore()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("délai de base non rétabli")
	}
	if context.Cause(ctx) != context.DeadlineExceeded {
		t.Fatalf("cause: %v", context.Cause(ctx))
	}
}
