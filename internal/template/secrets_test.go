package template

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/agardenat/clotr/internal/creds"
)

func TestSecretsKindRead(t *testing.T) {
	var tokens, calls atomic.Int32
	proxyAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("relay:proxypw"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != proxyAuth || r.URL.Host != "store.invalid" {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		switch r.URL.Path {
		case "/token":
			r.ParseForm()
			if r.Form.Get("grant_type") != "password" || r.Form.Get("username") != "svc" || r.Form.Get("password") != "storepw" || r.Form.Get("realm") != "main" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			tokens.Add(1)
			w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
		case "/items/7":
			calls.Add(1)
			if r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Write([]byte(`{"fields":{"login":"svc7","pass":"pw7"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	yaml := `name: x
kind: secrets
script: x.star
params:
  url: {type: url}
  proxy: {type: string}
connectors:
  api:
    driver: http
    base_url: "{{.url}}"
    proxy: "{{.proxy}}"
    proxy_auth: {user: relay, password_vault: "kv/relay#password"}
    auth:
      oauth2:
        grant: password
        token_url: "{{.url}}/token"
        username: svc
        password_vault: "kv/store#password"
        form: {realm: main, unused: ""}
`
	star := `
def read(ref):
    id, _, field = ref.partition("#")
    fields = json.decode(http.request("api", "GET", "/items/" + id).body)["fields"]
    name = field or "pass"
    if name not in fields:
        fail("champ absent : " + name)
    return fields[name]
`
	secrets := map[string]string{"kv/relay#password": "proxypw", "kv/store#password": "storepw"}
	read := creds.ReadVault
	creds.ReadVault = func(_ context.Context, ref string) (string, error) {
		if v, ok := secrets[ref]; ok {
			return v, nil
		}
		return "", errors.New("absent")
	}
	t.Cleanup(func() { creds.ReadVault = read })
	in, err := NewInstance("store", writeTemplate(t, yaml, star), map[string]any{"url": "http://store.invalid", "proxy": srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for ref, want := range map[string]string{"7#pass": "pw7", "7#login": "svc7", "7": "pw7"} {
		if v, err := in.SecretRead(ctx, ref); err != nil || v != want {
			t.Fatalf("%s : %q %v", ref, v, err)
		}
	}
	if tokens.Load() != 1 || calls.Load() != 3 {
		t.Fatalf("jetons %d (1 attendu), appels %d", tokens.Load(), calls.Load())
	}
	if _, err := in.SecretRead(ctx, "7#notes"); err == nil || !strings.Contains(err.Error(), "champ absent") {
		t.Fatalf("champ absent : %v", err)
	}
}

func TestSecretsKindSpec(t *testing.T) {
	for _, bad := range []string{
		"name: x\nkind: secrets\n",
		"name: x\nkind: secrets\nscript: x.star\ntargets: [{kind: a}]\n",
		"name: x\nkind: secrets\nscript: x.star\nconnectors:\n  s: {driver: ssh}\n",
		"name: x\nkind: secrets\nscript: x.star\nconnectors:\n  api: {driver: http, base_url: \"http://x\", proxy_auth: {user: u, password_vault: kv/p}}\n",
		"name: x\nkind: secrets\nscript: x.star\nconnectors:\n  api: {driver: http, base_url: \"http://x\", proxy: \"http://p:3128\", proxy_auth: {login: u}}\n",
		"name: x\nkind: secrets\nscript: x.star\nconnectors:\n  api: {driver: http, base_url: \"http://x\", auth: {oauth2: {grant: password, token_url: \"http://x/t\", password_vault: kv/p}}}\n",
		"name: x\nkind: secrets\nscript: x.star\nconnectors:\n  api: {driver: http, base_url: \"http://x\", auth: {oauth2: {grant: implicit, token_url: \"http://x/t\"}}}\n",
		"name: x\nkind: secrets\nscript: x.star\nconnectors:\n  api: {driver: http, base_url: \"http://x\", auth: {oauth2: {vault: kv/x, token_url: \"http://x/t\", username: u}}}\n",
	} {
		if _, err := Parse([]byte(bad), "x.yaml"); err == nil {
			t.Fatalf("spec acceptée à tort :\n%s", bad)
		}
	}
	tpl := writeTemplate(t, "name: x\nkind: secrets\nscript: x.star\n", "def other(ref):\n    return ref\n")
	if _, err := NewInstance("store", tpl, nil); err == nil || !strings.Contains(err.Error(), "read(ref)") {
		t.Fatalf("script sans read : %v", err)
	}
}
