package progress

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

func press(c *chat, k tea.KeyPressMsg) tea.Cmd {
	_, cmd := c.Update(k)
	return cmd
}

func TestChatTurn(t *testing.T) {
	t.Setenv("GLAMOUR_STYLE", "dark")
	var cancelled bool
	turn := func(ctx context.Context, req string, events Sink, answer func(string)) TurnResult {
		events.Emit(Event{Task: "planner", Kind: "plan", Plan: []PlanItem{{ID: "direct", Role: "collector", Goal: req}}})
		events.Emit(Event{Task: "direct", Kind: "start", Model: "p/fast"})
		answer("## Conclusion\n\nRAS")
		if req == "stop" {
			<-ctx.Done()
			cancelled = true
			return TurnResult{Err: ctx.Err()}
		}
		events.Emit(Event{Task: "direct", Kind: "done", Model: "p/fast", Step: 2})
		return TurnResult{Markdown: "## Conclusion\n\nRAS, **3 nœuds** Ready.", Info: []string{"models used: p/fast"}, Path: "/s/turns/001/report.md"}
	}
	c := newChat(context.Background(), ChatOptions{Title: "brave-otter", MaxSteps: 10, Turn: turn}, 90, 30)
	var mu sync.Mutex
	var queued []tea.Msg
	c.send = func(m tea.Msg) {
		mu.Lock()
		queued = append(queued, m)
		mu.Unlock()
	}
	if c.mode != modeInput {
		t.Fatal("sans demande initiale, la saisie doit être ouverte")
	}
	c.input.SetValue("état des nœuds")
	cmd := press(c, tea.KeyPressMsg{Code: tea.KeyEnter})
	if c.mode != modeRunning || cmd == nil {
		t.Fatal("entrée doit lancer le tour")
	}
	done := cmd()
	for _, m := range queued {
		c.Update(m)
	}
	c.refresh()
	live := ansi.Strip(c.vp.GetContent())
	if !strings.Contains(live, "❯ état des nœuds") || !strings.Contains(live, "Conclusion") || !strings.Contains(live, "collector") {
		t.Fatalf("pendant le tour:\n%s", live)
	}
	c.Update(done)
	out := ansi.Strip(c.vp.GetContent())
	if c.mode != modeIdle || !strings.Contains(out, "3 nœuds") || strings.Contains(out, "**") || !strings.Contains(out, "models used: p/fast") {
		t.Fatalf("après le tour (mode %d):\n%s", c.mode, out)
	}
	if !strings.Contains(ansi.Strip(c.footer()), "r reply") || !strings.Contains(ansi.Strip(c.header()), "brave-otter") {
		t.Fatalf("pied/entête: %s / %s", c.footer(), c.header())
	}
	if cmd := press(c, tea.KeyPressMsg{Code: 'c', Text: "c"}); cmd == nil {
		t.Fatal("c doit copier")
	}
	c.Update(copiedMsg{chars: 30, via: "OSC 52", path: "/s/turns/001/report.md"})
	if !strings.Contains(ansi.Strip(c.footer()), "copied as Markdown: 30 characters (OSC 52)") {
		t.Fatalf("statut copie: %s", ansi.Strip(c.footer()))
	}
	press(c, tea.KeyPressMsg{Code: 'r', Text: "r"})
	if c.mode != modeInput {
		t.Fatal("r doit ouvrir la saisie")
	}
	c.input.SetValue("stop")
	mu.Lock()
	queued = nil
	mu.Unlock()
	cmd = press(c, tea.KeyPressMsg{Code: tea.KeyEnter})
	finished := make(chan tea.Msg)
	go func() { finished <- cmd() }()
	for {
		mu.Lock()
		n := len(queued)
		mu.Unlock()
		if n >= 3 {
			break
		}
		runtime.Gosched()
	}
	mu.Lock()
	pending := append([]tea.Msg(nil), queued[:3]...)
	mu.Unlock()
	for _, m := range pending {
		c.Update(m)
	}
	press(c, tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if !strings.Contains(ansi.Strip(c.footer()), "interrupting") {
		t.Fatalf("statut interruption: %s", ansi.Strip(c.footer()))
	}
	c.Update(<-finished)
	if !cancelled || c.mode != modeIdle || len(c.entries) != 2 {
		t.Fatalf("interruption: cancelled=%v mode=%d", cancelled, c.mode)
	}
	if !errors.Is(c.last().result.Err, context.Canceled) || !strings.Contains(ansi.Strip(c.vp.GetContent()), "interrupted") {
		t.Fatalf("tour interrompu:\n%s", ansi.Strip(c.vp.GetContent()))
	}
	if cmd := press(c, tea.KeyPressMsg{Code: 'q', Text: "q"}); cmd == nil || cmd() != tea.Quit() {
		t.Fatal("q doit quitter")
	}
}
