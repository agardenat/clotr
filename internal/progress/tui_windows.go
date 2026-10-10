//go:build windows

package progress

import (
	"os"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/term"
)

func watchResize(t *TUI, out *os.File) {
	w0, h0, _ := term.GetSize(out.Fd())
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-tick.C:
			if w, h, err := term.GetSize(out.Fd()); err == nil && (w != w0 || h != h0) {
				w0, h0 = w, h
				t.p.Send(tea.WindowSizeMsg{Width: w, Height: h})
			}
		}
	}
}

func captureStderr(stderr *os.File, t *TUI) (*os.File, *os.File) {
	if stderr != os.Stderr {
		return stderr, nil
	}
	r, w, err := os.Pipe()
	if err != nil {
		return stderr, nil
	}
	os.Stderr = w
	t.restore = func() {
		os.Stderr = stderr
		_ = w.Close()
	}
	return stderr, r
}
