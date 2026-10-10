//go:build !windows

package creds

import "os"

func openConsole() (*Console, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &Console{In: f, Out: f}, nil
}
