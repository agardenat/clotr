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

func TestWrapListItems(t *testing.T) {
	t.Setenv("GLAMOUR_STYLE", "")
	md := "## Constats\n\n- Agent : « heartbeat delayed: 62s since last » à 08:47:38Z, deux occurrences seulement dans tout le fichier [E2.047]\n\n| a | b |\n|---|---|\n| x | y |\n\nFin."
	plain := ansi.Strip(Render(md, 50, true))
	lines := strings.Split(plain, "\n")
	bullet := -1
	for i, l := range lines {
		if ansi.StringWidth(l) > 46 {
			t.Errorf("ligne plus large que 46 colonnes: %q", l)
		}
		if strings.Contains(l, "• Agent") {
			bullet = i
		}
	}
	if bullet < 0 || !strings.HasPrefix(lines[bullet+1], strings.Repeat(" ", strings.Index(lines[bullet], "•")+2)) {
		t.Fatalf("suite de puce non indentée:\n%s", plain)
	}
	if !strings.Contains(plain, "[E2.047]") || strings.Contains(plain, "\n »") || !strings.Contains(plain, "│") {
		t.Fatalf("citation coupée, guillemet isolé ou tableau absent:\n%s", plain)
	}
}
