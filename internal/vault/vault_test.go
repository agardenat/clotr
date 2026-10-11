package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fake(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "tok" {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		switch r.URL.Path {
		case "/v1/sys/internal/ui/mounts/kv2/team/ssh":
			w.Write([]byte(`{"data":{"path":"kv2/","type":"kv","options":{"version":"2"}}}`))
		case "/v1/kv2/data/team/ssh":
			w.Write([]byte(`{"data":{"data":{"password":"s3cret","other":"x"},"metadata":{"version":3}}}`))
		case "/v1/sys/internal/ui/mounts/kv1/ssh":
			w.Write([]byte(`{"data":{"path":"kv1/","type":"kv","options":null}}`))
		case "/v1/kv1/ssh":
			w.Write([]byte(`{"data":{"pass":"v1pass"}}`))
		case "/v1/sys/internal/ui/mounts/legacy/ssh":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"errors":["permission denied"]}`))
		case "/v1/legacy/ssh":
			w.Write([]byte(`{"data":{"password":"legacy"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errors":[]}`))
		}
	}))
}

func TestRead(t *testing.T) {
	srv := fake(t)
	defer srv.Close()
	c := &Client{Addr: srv.URL, Token: "tok", HTTP: srv.Client()}
	ctx := context.Background()
	for ref, want := range map[string]string{"kv2/team/ssh": "s3cret", "/kv2/team/ssh#other": "x", "kv1/ssh#pass": "v1pass", "legacy/ssh": "legacy"} {
		if got, err := c.Read(ctx, ref); err != nil || got != want {
			t.Fatalf("%s: %q %v", ref, got, err)
		}
	}
	for ref, want := range map[string]string{"kv2/team/ssh#missing": `champ "missing" absent`, "kv2/none": "HTTP 404", "": "référence vide"} {
		if _, err := c.Read(ctx, ref); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v", ref, err)
		}
	}
	c.Token = "bad"
	if _, err := c.Read(ctx, "kv2/team/ssh"); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("jeton refusé: %v", err)
	}
}

func TestFromEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "")
	if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "VAULT_ADDR") {
		t.Fatalf("adresse absente: %v", err)
	}
	t.Setenv("VAULT_ADDR", "https://vault.example.test/")
	if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "vault login") {
		t.Fatalf("jeton absent: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".vault-token"), []byte("filetok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := FromEnv()
	if err != nil || c.Token != "filetok" || c.Addr != "https://vault.example.test" {
		t.Fatalf("jeton du fichier: %+v %v", c, err)
	}
	t.Setenv("VAULT_TOKEN", "envtok")
	if c, err = FromEnv(); err != nil || c.Token != "envtok" {
		t.Fatalf("VAULT_TOKEN prioritaire: %+v %v", c, err)
	}
}
