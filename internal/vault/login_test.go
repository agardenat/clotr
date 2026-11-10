package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agardenat/clotr/internal/browser"
)

type fakeVault struct {
	mu       sync.Mutex
	ttl      map[string]int
	renewTTL int
	renewed  int
	browsed  int
	nonce    string
	issued   int
}

func (f *fakeVault) handler(base *string) http.Handler {
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/v1/auth/token/lookup-self", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		ttl, ok := f.ttl[r.Header.Get("X-Vault-Token")]
		if !ok {
			write(w, 403, map[string]any{"errors": []string{"permission denied"}})
			return
		}
		write(w, 200, map[string]any{"data": map[string]any{"ttl": ttl, "renewable": true}})
	})
	mux.HandleFunc("/v1/auth/token/renew-self", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.renewed++
		f.ttl[r.Header.Get("X-Vault-Token")] = f.renewTTL
		write(w, 200, map[string]any{"auth": map[string]any{"lease_duration": f.renewTTL}})
	})
	mux.HandleFunc("/v1/auth/sso-oidc/oidc/auth_url", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.mu.Lock()
		f.nonce = b["client_nonce"]
		f.mu.Unlock()
		if b["redirect_uri"] == "" || b["role"] != "dev" {
			write(w, 400, map[string]any{"errors": []string{"bad request"}})
			return
		}
		write(w, 200, map[string]any{"data": map[string]any{"auth_url": *base + "/idp?" + url.Values{"redirect_uri": {b["redirect_uri"]}, "state": {"st1"}}.Encode()}})
	})
	mux.HandleFunc("/idp", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("redirect_uri")+"?state="+r.URL.Query().Get("state")+"&code=cd1", http.StatusFound)
	})
	mux.HandleFunc("/v1/auth/sso-oidc/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		defer f.mu.Unlock()
		if q.Get("state") != "st1" || q.Get("code") != "cd1" || q.Get("client_nonce") != f.nonce || r.Header.Get("X-Vault-Token") != "" {
			write(w, 400, map[string]any{"errors": []string{"invalid callback " + r.URL.RawQuery}})
			return
		}
		f.issued++
		tok := fmt.Sprintf("hvs.new%d", f.issued)
		f.ttl[tok] = 57600
		write(w, 200, map[string]any{"auth": map[string]any{"client_token": tok}})
	})
	return mux
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestEnsureLogin(t *testing.T) {
	f := &fakeVault{ttl: map[string]int{"hvs.long": 50000, "hvs.short": 600}, renewTTL: 57600}
	var base string
	srv := httptest.NewServer(f.handler(&base))
	defer srv.Close()
	base = srv.URL
	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "")
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, ".vault-token")
	prevPath, prevOpen := TokenPath, browser.Open
	TokenPath = func() string { return tokenFile }
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
			resp.Body.Close()
		}()
	}
	t.Cleanup(func() { TokenPath, browser.Open = prevPath, prevOpen })
	opts := LoginOptions{Path: "sso-oidc", Role: "dev", Port: freePort(t), MinTTL: 4 * time.Hour, Wait: 10 * time.Second}
	ctx := context.Background()
	counts := func() (int, int) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.browsed, f.renewed
	}
	token := func() string {
		b, _ := os.ReadFile(tokenFile)
		return string(b)
	}

	if err := EnsureLogin(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if b, _ := counts(); b != 1 || token() != "hvs.new1" {
		t.Fatalf("sans jeton: navigateur=%d jeton=%q", b, token())
	}
	if st, _ := os.Stat(tokenFile); st.Mode().Perm() != 0o600 {
		t.Fatalf("droits du jeton: %v", st.Mode())
	}

	os.WriteFile(tokenFile, []byte("hvs.long\n"), 0o600)
	if err := EnsureLogin(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if b, r := counts(); b != 1 || r != 0 {
		t.Fatalf("jeton valide: navigateur=%d renouvellements=%d", b, r)
	}

	os.WriteFile(tokenFile, []byte("hvs.short"), 0o600)
	if err := EnsureLogin(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if b, r := counts(); b != 1 || r != 1 || token() != "hvs.short" {
		t.Fatalf("jeton renouvelé: navigateur=%d renouvellements=%d jeton=%q", b, r, token())
	}

	f.mu.Lock()
	f.ttl["hvs.short"] = 600
	f.renewTTL = 1200
	f.mu.Unlock()
	if err := EnsureLogin(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if b, r := counts(); b != 2 || r != 2 || token() != "hvs.new2" {
		t.Fatalf("renouvellement trop court: navigateur=%d renouvellements=%d jeton=%q", b, r, token())
	}

	os.WriteFile(tokenFile, []byte("hvs.revoked"), 0o600)
	if err := EnsureLogin(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if b, _ := counts(); b != 3 || token() != "hvs.new3" {
		t.Fatalf("jeton révoqué: navigateur=%d jeton=%q", b, token())
	}

	t.Setenv("VAULT_TOKEN", "hvs.env")
	os.Remove(tokenFile)
	if err := EnsureLogin(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if b, _ := counts(); b != 3 {
		t.Fatalf("VAULT_TOKEN fourni: navigateur=%d", b)
	}
	t.Setenv("VAULT_TOKEN", "")

	bad := opts
	bad.Role = "absent"
	if err := EnsureLogin(ctx, bad); err == nil || !strings.Contains(err.Error(), "sso-oidc") {
		t.Fatalf("rôle refusé: %v", err)
	}
}
