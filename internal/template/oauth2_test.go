package template

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/agardenat/clotr/internal/creds"
)

func TestHTTPOAuth2ClientCredentials(t *testing.T) {
	var issued, refused atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tenant-1/oauth2/v2.0/token":
			r.ParseForm()
			if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "app-1" || r.Form.Get("client_secret") != "s3cret" || r.Form.Get("scope") != "https://api.example/.default" {
				refused.Add(1)
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"invalid_client","error_description":"bad credentials"}`))
				return
			}
			issued.Add(1)
			w.Write([]byte(`{"access_token":"tok-1","expires_in":"3599","token_type":"Bearer"}`))
		default:
			w.Write([]byte(r.Header.Get("Authorization")))
		}
	}))
	defer srv.Close()
	yaml := `name: x
script: x.star
params:
  url: {type: url}
  sp_vault: {type: string, default: ""}
  sp_client_id: {type: string, default: "{client-id}"}
connectors:
  api:
    driver: http
    base_url: "{{.url}}"
    auth:
      oauth2:
        vault: "{{.sp_vault}}"
        token_url: "{{.url}}/{tenant-id}/oauth2/v2.0/token"
        client_id: "{{.sp_client_id}}"
        client_secret: "{client-secret}"
        scope: "https://api.example/.default"
  other:
    driver: http
    base_url: "{{.url}}"
    auth:
      oauth2:
        vault: "{{.sp_vault}}"
        token_url: "{{.url}}/{tenant-id}/oauth2/v2.0/token"
        client_id: "{{.sp_client_id}}"
        client_secret: "{client-secret}"
        scope: "https://api.example/.default"
`
	star := `
tool(name = "get", description = "d", schema = {"type": "object"}, fn = lambda a: http.request(a.get("conn", "api"), "GET", "/x").body)

def discover(ctx):
    return {"targets": [{"name": "a", "kind": "a"}]}
`
	secrets := map[string]string{"kv/acme/sp#client-id": "app-1", "kv/acme/sp#client-secret": "s3cret", "kv/acme/sp#tenant-id": "tenant-1", "kv/beta/sp#appId": "app-1", "kv/beta/sp#client-secret": "faux", "kv/beta/sp#tenant-id": "tenant-1"}
	read := creds.ReadVault
	var reads atomic.Int32
	creds.ReadVault = func(_ context.Context, ref string) (string, error) {
		reads.Add(1)
		if v, ok := secrets[ref]; ok {
			return v, nil
		}
		return "", errors.New("absent")
	}
	t.Cleanup(func() { creds.ReadVault = read })
	tpl := writeTemplate(t, yaml, star)

	in, err := NewInstance("oauth", tpl, map[string]any{"url": srv.URL, "sp_vault": "kv/acme/sp"})
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	tools := instanceTools(t, in)
	for _, conn := range []string{"api", "other", "api"} {
		if out, err := tools["get"](map[string]any{"conn": conn}); err != nil || out != "Bearer tok-1" {
			t.Fatalf("%s : %q %v", conn, out, err)
		}
	}
	if issued.Load() != 1 || reads.Load() != 6 {
		t.Fatalf("jetons émis %d (1 attendu, partagé et mis en cache), lectures Vault %d", issued.Load(), reads.Load())
	}

	in2, _ := NewInstance("oauth-beta", tpl, map[string]any{"url": srv.URL, "sp_vault": "kv/beta/sp", "sp_client_id": "{appId}"})
	err = in2.Prepare(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid_client bad credentials") || strings.Contains(err.Error(), "faux") {
		t.Fatalf("refus attendu sans le secret dans le message : %v", err)
	}
	in3, _ := NewInstance("oauth-missing", tpl, map[string]any{"url": srv.URL, "sp_vault": "kv/none/sp"})
	if err := in3.Prepare(context.Background()); err == nil || !strings.Contains(err.Error(), "kv/none/sp") {
		t.Fatalf("secret absent : %v", err)
	}
	off, _ := NewInstance("oauth-off", tpl, map[string]any{"url": srv.URL})
	if err := off.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if out, err := instanceTools(t, off)["get"](map[string]any{}); err != nil || out != "" {
		t.Fatalf("sans vault, aucune authentification attendue : %q %v", out, err)
	}

	for _, bad := range []string{
		"name: x\ntargets: [{kind: a}]\nconnectors:\n  api: {driver: http, base_url: \"http://x\", auth: {oauth2: {vault: kv/x}}}\n",
		"name: x\ntargets: [{kind: a}]\nconnectors:\n  api: {driver: http, base_url: \"http://x\", auth: {oauth2: {vault: kv/x, token_url: \"http://x/t\", audience: y}}}\n",
		"name: x\ntargets: [{kind: a}]\nconnectors:\n  api: {driver: http, base_url: \"http://x\", auth: {oauth2: {vault: kv/x, token_url: \"http://x/t\"}, password_env: P}}\n",
	} {
		if _, err := Parse([]byte(bad), "x.yaml"); err == nil {
			t.Fatalf("accepté : %s", bad)
		}
	}
}
