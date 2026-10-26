package ssh

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/i18n"
)

type Local struct {
	sem chan struct{}
}

func NewLocal(maxConns int) *Local {
	if maxConns <= 0 {
		maxConns = 4
	}
	return &Local{sem: make(chan struct{}, maxConns)}
}

func (l *Local) Close() {}

func (l *Local) ExecInput(ctx context.Context, _ Endpoint, cmd, stdin string, maxBytes int) (Result, error) {
	select {
	case l.sem <- struct{}{}:
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
	defer func() { <-l.sem }()
	sh, err := exec.LookPath("sh")
	if err != nil {
		return Result{}, i18n.E("ssh.local_shell", err)
	}
	c := exec.CommandContext(ctx, sh, "-c", cmd)
	killGroup(c)
	c.WaitDelay = 2 * time.Second
	stdout := &limitBuffer{max: maxBytes}
	stderr := &limitBuffer{max: 8 << 10}
	c.Stdout, c.Stderr = stdout, stderr
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	err = c.Run()
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	r := Result{Stdout: stdout.String(), Stderr: stderr.String(), Truncated: stdout.truncated}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		r.Exit = ee.ExitCode()
		return r, nil
	}
	return r, err
}
