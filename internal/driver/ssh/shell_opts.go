package ssh

import (
	"context"
	"regexp"
	"time"
)

type ShellOptions struct {
	Command     []string
	Then        []string
	Ready       *regexp.Regexp
	Prompt      *regexp.Regexp
	MaxConns    int
	OpenTimeout time.Duration
	Ask         func(ctx context.Context, question string) (string, error)
	User        string
	Login       func(ctx context.Context) (user, pass string, err error)
	Forget      func(user string)
}

var (
	DefaultShellReady  = regexp.MustCompile(`[$#] ?$`)
	DefaultShellPrompt = regexp.MustCompile(`(?i)(password|passphrase|mot de passe)[^:\n]*: ?$`)
)
