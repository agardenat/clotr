package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agardenat/clotr/internal/access"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/template"
	"github.com/agardenat/clotr/internal/tools"
)

func TestAccessFlag(t *testing.T) {
	err := cmdRun(context.Background(), &options{accessFlag: "write"}, []string{"x"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "write") {
		t.Fatalf("niveau inconnu: %v", err)
	}
	root := newRoot()
	run, _, err := root.Find([]string{"run"})
	if err != nil || run.Flags().Lookup("access") == nil || run.Flags().Lookup("access").DefValue != "" {
		t.Fatalf("flag --access: %v", err)
	}
	for _, name := range []string{"session", "plan"} {
		c, _, _ := root.Find([]string{name})
		if c.Flags().Lookup("access") != nil {
			t.Fatalf("--access sur %s", name)
		}
	}
}

func TestNewInstanceAccess(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x.star"), []byte("tool(name = 'r', description = 'd', schema = {'type': 'object'}, fn = lambda a: 1)\ntool(name = 'e', description = 'd', schema = {'type': 'object'}, fn = lambda a: 1, access = 'exec')\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "x.yaml"), []byte("name: x\nscript: x.star\ncommands: {allow: [\"php -v\"]}\n"), 0o600)
	set, err := template.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	tpl, _ := set.Get("x")
	ic := config.Instance{Name: "i", Template: "x", Commands: access.Rules{Allow: []string{"openssl version"}}}
	in, err := newInstance(&config.Config{}, ic, tpl, access.Read)
	if err != nil || strings.Join(in.ToolNames(), ",") != "i_r" {
		t.Fatalf("read: %v %v", in.ToolNames(), err)
	}
	in, err = newInstance(&config.Config{}, ic, tpl, access.Exec)
	if err != nil || strings.Join(in.ToolNames(), ",") != "i_r,i_e" || in.Access() != access.Exec {
		t.Fatalf("exec: %v %v", in.ToolNames(), err)
	}
	ic.Commands = access.Rules{Allow: []string{"**"}}
	if _, err := newInstance(&config.Config{}, ic, tpl, access.Exec); err == nil {
		t.Fatal("commands invalide accepté")
	}
}

func TestClientAccessLevel(t *testing.T) {
	cfg := &config.Config{Clients: []config.Client{{Name: "acme", Access: "exec"}}}
	acme, solo := config.Instance{Name: "acme-lake", Client: "acme"}, config.Instance{Name: "solo"}
	o := &options{}
	if o.levelFor(cfg, acme) != access.Exec || o.levelFor(cfg, solo) != access.Read {
		t.Fatal("niveau du client")
	}
	o = &options{accessSet: true, access: access.Read}
	if o.levelFor(cfg, acme) != access.Read {
		t.Fatal("--access read doit primer sur le client")
	}
	o = &options{accessSet: true, access: access.Create}
	if o.levelFor(cfg, solo) != access.Create {
		t.Fatal("--access create pour toutes les instances")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x.star"), []byte("tool(name = 'r', description = 'd', schema = {'type': 'object'}, fn = lambda a: 1)\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "x.yaml"), []byte("name: x\nscript: x.star\n"), 0o600)
	set, err := template.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	tpl, _ := set.Get("x")
	reg := tools.NewRegistry(0)
	var ins []*template.Instance
	for _, c := range []struct {
		name  string
		level access.Level
	}{{"a", access.Exec}, {"b", access.Read}, {"c", access.Create}, {"d", access.Exec}} {
		in, err := newInstance(cfg, config.Instance{Name: c.name, Template: "x"}, tpl, c.level)
		if err != nil {
			t.Fatal(err)
		}
		if err := in.Discover(context.Background(), "", 0, true); err != nil {
			t.Fatal(err)
		}
		ins = append(ins, in)
		if c.name != "d" {
			reg.Add(in.Tools()...)
		}
	}
	if got := accessSummary(ins, reg); got != "exec (a), create (c)" {
		t.Fatal(got)
	}
	if !strings.Contains(strings.Join(ins[0].EnvironmentLines(), "\n"), "Niveau d'accès exec") {
		t.Fatal("consigne exec absente")
	}
	if strings.Contains(strings.Join(ins[1].EnvironmentLines(), "\n"), "Niveau d'accès") {
		t.Fatal("consigne en read")
	}
}
