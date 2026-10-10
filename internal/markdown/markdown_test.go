package markdown

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

func TestRender(t *testing.T) {
	t.Setenv("GLAMOUR_STYLE", "")
	md := "# Conclusion\n\nLe nœud **worker-2** est saturé [E004].\n\n| pod | état |\n|---|---|\n| api | CrashLoopBackOff |\n\n```sh\nkubectl get pods\n```\n"
	out := Render(md, 60, true)
	if out == md || !strings.Contains(out, "\x1b[") {
		t.Fatalf("rendu sans styles:\n%s", out)
	}
	plain := ansi.Strip(out)
	for _, want := range []string{"Conclusion", "worker-2", "[E004]", "CrashLoopBackOff", "kubectl get pods"} {
		if !strings.Contains(plain, want) {
			t.Errorf("%q absent du rendu:\n%s", want, plain)
		}
	}
	for _, l := range strings.Split(plain, "\n") {
		if ansi.StringWidth(l) > 60 {
			t.Errorf("ligne plus large que 60 colonnes: %q", l)
		}
	}
	if Style(false) != "light" {
		t.Errorf("style clair: %s", Style(false))
	}
	t.Setenv("GLAMOUR_STYLE", "dracula")
	if Style(false) != "dracula" {
		t.Errorf("GLAMOUR_STYLE ignoré")
	}
}
