package main

import (
	"testing"

	"github.com/agardenat/clotr/internal/config"
)

func TestRenderTunnel(t *testing.T) {
	cl := config.Client{Name: "acme", Vars: map[string]string{"cmp": "CMP-0000"}, Projects: []config.Project{{Name: "PRJ-0000"}}}
	tc, err := renderTunnel(config.Tunnel{Hops: []string{"10.0.0.1"}, PasswordVault: "kv/{{.cmp}}/{{.project}}/adm"}, clientVars(cl, "PRJ-0000"))
	if err != nil || tc.PasswordVault != "kv/CMP-0000/PRJ-0000/adm" || tc.Hops[0] != "10.0.0.1" {
		t.Fatalf("rendu: %+v %v", tc, err)
	}
	if _, err := renderTunnel(config.Tunnel{Hops: []string{"x"}, PasswordVault: "kv/{{.project}}"}, clientVars(cl, "")); err == nil {
		t.Fatal("variable inconnue acceptée")
	}
}
