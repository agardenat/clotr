package progress

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"

	"github.com/agardenat/clotr/internal/i18n"
)

func TestBoard(t *testing.T) {
	clock := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	b := newBoard(10)
	b.now = func() time.Time { return clock }
	b.start = clock
	b.width = 160
	b.apply(Event{Task: "planner", Kind: "start", Model: "local/model-l"})
	b.apply(Event{Task: "planner", Kind: "plan", Model: "local/model-l", Plan: []PlanItem{
		{ID: "t1", Role: "collector", Goal: "nodes"},
		{ID: "t2", Role: "analyst", Goal: "pods", DependsOn: []string{"t1"}},
	}})
	b.apply(Event{Task: "planner", Kind: "done", Model: "local/model-l", Detail: "2 tâches"})
	b.apply(Event{Task: "synthesizer", Kind: "start", Model: "local/model-l"})
	b.apply(Event{Task: "t1", Kind: "start", Model: "local/model-s", Detail: "nodes"})
	clock = clock.Add(3 * time.Second)
	b.apply(Event{Task: "t1", Kind: "step", Model: "local/model-s", Step: 5})
	b.apply(Event{Task: "t1", Kind: "tool", Detail: `k8s_list {"resource":"nodes"}`})
	out := ansi.Strip(b.render())
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 5 {
		t.Fatalf("lignes: %d\n%s", len(lines), out)
	}
	ids := []string{"planner", "t1", "t2", "synthesizer"}
	for i, id := range ids {
		if !strings.Contains(lines[i+1], id) {
			t.Errorf("ligne %d sans %s: %s", i+1, id, lines[i+1])
		}
	}
	if !strings.Contains(lines[0], "tasks 0/2") || !strings.Contains(lines[0], "1 tool call") {
		t.Errorf("entête: %s", lines[0])
	}
	if !strings.Contains(lines[1], "✓") || !strings.Contains(lines[2], "█████░░░░░") || !strings.Contains(lines[2], "step 5") || !strings.Contains(lines[2], "tool k8s_list") {
		t.Errorf("lignes: %s\n%s", lines[1], lines[2])
	}
	if !strings.Contains(lines[3], "waiting for t1") || !strings.Contains(lines[3], "·") {
		t.Errorf("attente: %s", lines[3])
	}
	b.apply(Event{Task: "t1", Kind: "done", Detail: "3 constats", Cost: 0.0123, Step: 6})
	if l := ansi.Strip(b.line(b.idx["t1"])); !strings.Contains(l, "6 steps") || strings.Count(l, "0.0123 $") != 1 {
		t.Errorf("tâche terminée: %s", l)
	}
	b.apply(Event{Task: "t2", Kind: "start", Model: "m"})
	b.apply(Event{Task: "t2", Kind: "limit", Detail: "10-step limit reached, forced conclusion", Step: 10})
	if l := ansi.Strip(b.line(b.idx["t2"])); !strings.Contains(l, "step 10") || !strings.Contains(l, "forced conclusion") {
		t.Errorf("limite: %s", l)
	}
	b.apply(Event{Task: "t3", Kind: "start", Model: "m"})
	b.apply(Event{Task: "t3", Kind: "time_limit", Detail: "time almost up, forced conclusion", Step: 7})
	b.apply(Event{Task: "t3", Kind: "done", Detail: "4 findings", Step: 7})
	if l := ansi.Strip(b.line(b.idx["t3"])); !strings.Contains(l, "7 steps") || !strings.Contains(l, "4 findings · time limit") {
		t.Errorf("limite de temps: %s", l)
	}
	b.apply(Event{Task: "t2", Kind: "failed", Detail: "HTTP 401"})
	b.idx["t2"].limited = false
	out = ansi.Strip(b.render())
	if !strings.Contains(out, "tasks 2/3 (1 failed)") || !strings.Contains(out, "0.0123 $") || !strings.Contains(out, "✗") {
		t.Errorf("fin:\n%s", out)
	}
	for _, l := range strings.Split(out, "\n") {
		if ansi.StringWidth(l) > 160 {
			t.Errorf("ligne trop large (%d): %s", ansi.StringWidth(l), l)
		}
	}
}

func TestBoardFrench(t *testing.T) {
	i18n.SetReport("en")
	i18n.SetUI("fr")
	defer i18n.SetUI("en")
	b := newBoard(10)
	b.width = 160
	b.apply(Event{Task: "planner", Kind: "plan", Plan: []PlanItem{{ID: "t1", Role: "collector"}, {ID: "t2", Role: "analyst", DependsOn: []string{"t1"}}}})
	b.apply(Event{Task: "t1", Kind: "start", Model: "m"})
	b.apply(Event{Task: "t1", Kind: "step", Model: "m", Step: 3})
	out := ansi.Strip(b.render())
	for _, want := range []string{"en cours", "tâches 0/2", "étape 3", "réflexion…", "attend t1", "0 appel d'outil"} {
		if !strings.Contains(out, want) {
			t.Errorf("sans %q:\n%s", want, out)
		}
	}
	b.apply(Event{Task: "t1", Kind: "done", Step: 5, Detail: "x"})
	if l := ansi.Strip(b.line(b.idx["t1"])); !strings.Contains(l, "5 étapes") {
		t.Errorf("terminé: %s", l)
	}
}

func TestBoardHoldsLinesUntilFirstFrame(t *testing.T) {
	b := newBoard(10)
	if _, cmd := b.Update(logMsg("session: x")); cmd != nil {
		t.Fatal("ligne imprimée avant le premier rendu")
	}
	if _, cmd := b.Update(eventMsg(Event{Task: "budget", Model: "p/m", Detail: "d"})); cmd != nil {
		t.Fatal("avertissement imprimé avant le premier rendu")
	}
	if len(b.pending) != 2 {
		t.Fatalf("pending = %d, attendu 2", len(b.pending))
	}
	if _, cmd := b.Update(tickMsg(time.Now())); cmd == nil || !b.ready || b.pending != nil {
		t.Fatal("lignes en attente non imprimées au premier tick")
	}
	if _, cmd := b.Update(logMsg("après")); cmd == nil {
		t.Fatal("ligne non imprimée après le premier rendu")
	}
}

func TestBoardTrailingLineOnlyWhenFinished(t *testing.T) {
	b := newBoard(10)
	b.apply(Event{Task: "planner", Kind: "start", Model: "p/m"})
	if strings.HasSuffix(b.render(), "\n") {
		t.Fatal("ligne vide en bas du tableau pendant le run")
	}
	b.finished = true
	if !strings.HasSuffix(b.render(), "\n") {
		t.Fatal("ligne finale absente : la sortie suivante écraserait la dernière ligne")
	}
}
