//go:build !windows

package creds

import (
	"os"

	"golang.org/x/sys/unix"
)

func openConsole() (*Console, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	if pgrp, err := unix.IoctlGetInt(int(f.Fd()), unix.TIOCGPGRP); err == nil && pgrp != unix.Getpgrp() {
		_ = f.Close()
		return nil, ErrBackground
	}
	return &Console{In: f, Out: f}, nil
}
