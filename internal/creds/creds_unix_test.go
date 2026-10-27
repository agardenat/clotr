//go:build !windows

package creds

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/creack/pty"
)

func TestResolvePrompter(t *testing.T) {
	ptm, tty, err := pty.Open()
	if err != nil {
		t.Skip(err)
	}
	defer ptm.Close()
	OpenTTY = func() (*Console, error) {
		f, err := os.OpenFile(tty.Name(), os.O_RDWR, 0)
		return &Console{In: f, Out: f}, err
	}
	suspended := false
	Suspend = func() func() { suspended = true; return func() {} }
	var questions []string
	Prompter = func(_ context.Context, _ *os.File, q string, secret bool) (string, error) {
		questions = append(questions, q)
		if secret {
			return "s3cret", nil
		}
		return " bob\n", nil
	}
	t.Cleanup(func() { OpenTTY, Suspend, Prompter = openConsole, nil, nil; tty.Close() })
	p, err := Resolve(context.Background(), "", "", "", "prompter-test")
	if err != nil || p.User != "bob" || p.Pass != "s3cret" {
		t.Fatalf("%+v %v", p, err)
	}
	if len(questions) != 2 || !strings.Contains(questions[1], "bob") || suspended {
		t.Fatalf("questions %q, suspendu %v", questions, suspended)
	}
	Prompter = func(context.Context, *os.File, string, bool) (string, error) { return "", ErrNoPrompter }
	go func() { _, _ = ptm.Write([]byte("repli\n")) }()
	if s, err := Ask(context.Background(), "question : "); err != nil || strings.TrimSpace(s) != "repli" {
		t.Fatalf("repli sur le terminal : %q %v", s, err)
	}
}
