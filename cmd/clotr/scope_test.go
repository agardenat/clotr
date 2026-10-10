package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/template"
	"github.com/agardenat/clotr/internal/tools"
)

func TestScopeHidesUnmentionedInstance(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte("name: acme\nkeywords: [widget]\ntargets:\n  - {kind: k, name: lake}\ntools:\n  - kind: inventory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := template.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	tpl, _ := set.Get("acme")
	in, err := template.NewInstance("lab", tpl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Defer(context.Background(), "", time.Hour, false); err != nil {
		t.Fatal(err)
	}
	rt := &app{registry: tools.NewRegistry(100), audit: audit.Nop(), instances: []*template.Instance{in}, baseEnv: []string{"- Fichiers locaux: /var/log"}, instanceEnv: map[string][]string{"lab": in.EnvironmentLines()}}
	rt.registry.Add(in.Tools()...)
	rt.registry.AddGroup(in.ToolPrefix())
	reg, env := rt.scope(&options{}, "pourquoi Alice ne fait plus partie du groupe Finance ?")
	if reg.Len() != 0 || !strings.Contains(env, "non proposée pour cette demande") || strings.Contains(env, "lake") {
		t.Fatalf("instance proposée sans mention: %v\n%s", reg.Names(), env)
	}
	if reg, env := rt.scope(&options{}, "santé du widget principal"); reg.Len() != 1 || !strings.Contains(env, "lake") {
		t.Fatalf("instance mentionnée non proposée: %v\n%s", reg.Names(), env)
	}
	if reg, _ := rt.scope(&options{tools: []string{"lab"}}, "question sans rapport"); reg.Len() != 1 {
		t.Fatal("-t lab doit forcer l'instance")
	}
}
