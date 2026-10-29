//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package progress

import "golang.org/x/sys/unix"

const (
	ioctlGetTermios = unix.TIOCGETA
	ioctlSetTermios = unix.TIOCSETA
)

const flushRead = 1

func flushInput(fd int) {
	_ = unix.IoctlSetPointerInt(fd, unix.TIOCFLUSH, flushRead)
}
