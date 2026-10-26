package ssh

import (
	"context"
	"errors"
)

type Shell struct{}

func NewShell(ShellOptions) (*Shell, error) {
	return nil, errors.New("shell driver: not supported on Windows")
}

func (*Shell) ExecInput(context.Context, Endpoint, string, string, int) (Result, error) {
	return Result{}, errors.New("shell driver: not supported on Windows")
}

func (*Shell) Close() {}
