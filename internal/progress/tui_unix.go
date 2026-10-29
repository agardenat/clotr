//go:build !windows

package progress

import (
	"os"
	"os/signal"
	"syscall"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/term"
	"golang.org/x/sys/unix"
)

func promptMode(f *os.File) (restore func(), err error) {
	fd := int(f.Fd())
	t, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return nil, err
	}
	saved := *t
	t.Lflag &^= unix.ECHO | unix.ICANON
	t.Cc[unix.VMIN], t.Cc[unix.VTIME] = 1, 0
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, t); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, ioctlSetTermios, &saved) }, nil
}

func quietInput(f *os.File) (restore func()) {
	fd := int(f.Fd())
	t, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return func() {}
	}
	saved := *t
	t.Lflag &^= unix.ECHO | unix.ICANON
	t.Cc[unix.VMIN], t.Cc[unix.VTIME] = 1, 0
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, t); err != nil {
		return func() {}
	}
	return func() {
		flushInput(fd)
		_ = unix.IoctlSetTermios(fd, ioctlSetTermios, &saved)
	}
}

func discardInput(f *os.File) {
	flushInput(int(f.Fd()))
}

func watchResize(p *tea.Program, stop <-chan struct{}, out *os.File) {
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	for {
		select {
		case <-stop:
			return
		case <-winch:
			if w, h, err := term.GetSize(out.Fd()); err == nil {
				p.Send(tea.WindowSizeMsg{Width: w, Height: h})
			}
		}
	}
}

func captureStderr(stderr *os.File) (*os.File, *os.File, func()) {
	fd := int(stderr.Fd())
	saved, err := unix.Dup(fd)
	if err != nil {
		return stderr, nil, nil
	}
	r, w, err := os.Pipe()
	if err != nil {
		_ = unix.Close(saved)
		return stderr, nil, nil
	}
	if err := unix.Dup2(int(w.Fd()), fd); err != nil {
		_ = unix.Close(saved)
		_ = r.Close()
		_ = w.Close()
		return stderr, nil, nil
	}
	_ = w.Close()
	return os.NewFile(uintptr(saved), "terminal"), r, func() {
		_ = unix.Dup2(saved, fd)
	}
}
