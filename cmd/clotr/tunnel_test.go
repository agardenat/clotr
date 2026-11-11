package main

import (
	"testing"

	"github.com/agardenat/clotr/internal/config"
)

func TestRenderTunnel(t *testing.T) {
	cl := config.Client{Name: "acme", Vars: map[string]string{"code": "C-0000"}, Projects: []config.Project{{Name: "P-0000"}}}
	tc, err := renderTunnel(config.Tunnel{Hops: []string{"10.0.0.1"}, PasswordVault: "kv/{{.code}}/{{.project}}/adm"}, clientVars(cl, "P-0000"))
	if err != nil || tc.PasswordVault != "kv/C-0000/P-0000/adm" || tc.Hops[0] != "10.0.0.1" {
		t.Fatalf("rendu: %+v %v", tc, err)
	}
	if _, err := renderTunnel(config.Tunnel{Hops: []string{"x"}, PasswordVault: "kv/{{.project}}"}, clientVars(cl, "")); err == nil {
		t.Fatal("variable inconnue acceptée")
	}
}
