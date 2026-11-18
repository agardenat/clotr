package template

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestModesHintsOnlyInTheirMode(t *testing.T) {
	src := "name: x\ntargets: [{kind: a, name: n1}]\ntools: [{kind: inventory}]\nhints: consigne générale\nmodes:\n  upgrade:\n    hints: |\n      lire la documentation de mise à jour\n    checklist: [version, sauvegardes]\n"
	if _, err := Parse([]byte(strings.Replace(src, "upgrade:", "panne:", 1)), filepath.Join(t.TempDir(), "x.yaml")); err == nil || !strings.Contains(err.Error(), "modes.panne") {
		t.Fatalf("mode inconnu accepté : %v", err)
	}
	tpl, err := Parse([]byte(src), filepath.Join(t.TempDir(), "x.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	env := func(mode string) string {
		in, err := NewInstance("i", tpl, nil)
		if err != nil {
			t.Fatal(err)
		}
		in.Mode = mode
		if err := in.Defer(context.Background(), t.TempDir(), time.Hour, false); err != nil {
			t.Fatal(err)
		}
		return strings.Join(in.EnvironmentLines(), "\n")
	}
	plain := env("")
	if !strings.Contains(plain, "consigne générale") || strings.Contains(plain, "lire la documentation") || strings.Contains(plain, "sauvegardes") {
		t.Fatalf("hors mode :\n%s", plain)
	}
	up := env("upgrade")
	if !strings.Contains(up, "consigne générale") || !strings.Contains(up, "  lire la documentation de mise à jour") || !strings.Contains(up, modeChecklistHint+"version ; sauvegardes.") {
		t.Fatalf("mode upgrade :\n%s", up)
	}
}
