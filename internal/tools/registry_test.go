package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type fake struct{ name string }

func (f fake) Name() string            { return f.name }
func (f fake) Description() string     { return "desc " + f.name }
func (f fake) Schema() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }
func (f fake) Call(context.Context, json.RawMessage) (string, error) {
	return strings.Repeat("é", 100), nil
}

func TestRegistry(t *testing.T) {
	r := NewRegistry(51)
	r.Add(fake{"k8s_list"}, fake{"k8s_get"}, fake{"fs_read"}, fake{"mcp_srv_a"})
	got, err := r.Expand([]string{"k8s", "fs_read", "mcp_srv*"})
	if err != nil || strings.Join(got, ",") != "k8s_list,k8s_get,fs_read,mcp_srv_a" {
		t.Fatalf("expand: %v %v", got, err)
	}
	if _, err := r.Expand([]string{"nope"}); err == nil {
		t.Fatal("outil inconnu accepté")
	}
	if _, err := r.Call(context.Background(), []string{"k8s_list"}, "fs_read", "{}"); err == nil {
		t.Fatal("outil hors scope accepté")
	}
	out, err := r.Call(context.Background(), []string{"fs_read"}, "fs_read", "")
	if err != nil || out != strings.Repeat("é", 100) {
		t.Fatalf("sortie complète attendue: %q %v", out, err)
	}
	if c := r.Clip(out, ""); !strings.Contains(c, "[truncated") || !strings.Contains(c, "affiner la requête") || !strings.HasPrefix(c, strings.Repeat("é", 25)) {
		t.Fatalf("troncature: %q", c)
	}
	if c := r.Clip("a\nb\n"+strings.Repeat("x", 100), "E007"); !strings.Contains(c, "à partir de la ligne 3") || !strings.Contains(c, "evidence_read id=E007") {
		t.Fatalf("troncature avec preuve: %q", c)
	}
	if _, err := r.Call(context.Background(), []string{"fs_read"}, "fs_read", "{bad"); err == nil {
		t.Fatal("JSON invalide accepté")
	}
}

func TestStringList(t *testing.T) {
	var v struct {
		A StringList `json:"a"`
		B StringList `json:"b"`
	}
	if err := json.Unmarshal([]byte(`{"a":["x","y"],"b":"x, y ,z"}`), &v); err != nil || len(v.A) != 2 || len(v.B) != 3 || v.B[2] != "z" {
		t.Fatalf("%+v %v", v, err)
	}
}

func TestCompanions(t *testing.T) {
	r := NewRegistry(100)
	for _, n := range []string{"prod_inventory", "prod_ssh_tail", "k8s_list"} {
		r.Add(fake{n})
	}
	r.AddCompanions("prod_", "prod_inventory", "prod_absent")
	if got := r.Companions([]string{"prod_ssh_tail"}); len(got) != 1 || got[0] != "prod_inventory" {
		t.Fatalf("compagnons: %v", got)
	}
	if got := r.Companions([]string{"k8s_list"}); len(got) != 0 {
		t.Fatalf("compagnons hors préfixe: %v", got)
	}
}

func TestGroupMembers(t *testing.T) {
	r := NewRegistry(100)
	for _, n := range []string{"prod_inventory", "prod_api_get", "prod_ssh_tail", "k8s_list"} {
		r.Add(fake{n})
	}
	r.AddGroup("prod_")
	if got := r.GroupMembers([]string{"prod_api_get"}); len(got) != 3 {
		t.Fatalf("groupe: %v", got)
	}
	if got := r.GroupMembers([]string{"k8s_list"}); len(got) != 0 {
		t.Fatalf("hors groupe: %v", got)
	}
}

func TestWithout(t *testing.T) {
	r := NewRegistry(100)
	for _, n := range []string{"k8s_list", "prod_ssh_read", "prod_inventory", "production_x"} {
		r.Add(fake{n})
	}
	r.AddGroup("prod")
	r.AddCompanions("prod", "k8s_list")
	w := r.Without("prod")
	if got := strings.Join(w.Names(), ","); got != "k8s_list,production_x" {
		t.Fatalf("outils: %s", got)
	}
	if _, err := w.Expand([]string{"prod"}); err == nil {
		t.Fatal("groupe masqué encore accepté")
	}
	if len(r.Names()) != 4 {
		t.Fatal("registre d'origine modifié")
	}
}
