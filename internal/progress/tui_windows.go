//go:build windows

package progress

import (
	"os"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/term"
	"golang.org/x/sys/windows"
)

func promptMode(f *os.File) (restore func(), err error) {
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return nil, err
	}
	if err := windows.SetConsoleMode(h, mode&^(windows.ENABLE_ECHO_INPUT|windows.ENABLE_LINE_INPUT)); err != nil {
		return nil, err
	}
	return func() { _ = windows.SetConsoleMode(h, mode) }, nil
}

func quietInput(f *os.File) (restore func()) {
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return func() {}
	}
	if err := windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT); err != nil {
		return func() {}
	}
	return func() {
		_ = windows.FlushConsoleInputBuffer(h)
		_ = windows.SetConsoleMode(h, mode)
	}
}

func discardInput(f *os.File) {
	_ = windows.FlushConsoleInputBuffer(windows.Handle(f.Fd()))
}

func watchResize(p *tea.Program, stop <-chan struct{}, out *os.File) {
	w0, h0, _ := term.GetSize(out.Fd())
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			if w, h, err := term.GetSize(out.Fd()); err == nil && (w != w0 || h != h0) {
				w0, h0 = w, h
				p.Send(tea.WindowSizeMsg{Width: w, Height: h})
			}
		}
	}
}

func captureStderr(stderr *os.File) (*os.File, *os.File, func()) {
	if stderr != os.Stderr {
		return stderr, nil, nil
	}
	r, w, err := os.Pipe()
	if err != nil {
		return stderr, nil, nil
	}
	os.Stderr = w
	return stderr, r, func() {
		os.Stderr = stderr
		_ = w.Close()
	}
}
