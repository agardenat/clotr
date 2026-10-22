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
