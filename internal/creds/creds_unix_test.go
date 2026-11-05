//go:build !windows

package creds

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

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

func TestAskWithin(t *testing.T) {
	ptm, tty, err := pty.Open()
	if err != nil {
		t.Skip(err)
	}
	defer ptm.Close()
	OpenTTY = func() (*Console, error) {
		f, err := os.OpenFile(tty.Name(), os.O_RDWR, 0)
		return &Console{In: f, Out: f}, err
	}
	t.Cleanup(func() { OpenTTY = openConsole; tty.Close() })
	go func() {
		buf := make([]byte, 1024)
		for {
			if _, err := ptm.Read(buf); err != nil {
				return
			}
		}
	}()
	if _, err := AskWithin(context.Background(), "question : ", 50*time.Millisecond); !errors.Is(err, ErrNoAnswer) {
		t.Fatalf("attendu ErrNoAnswer : %v", err)
	}
	go func() { _, _ = ptm.Write([]byte("suivante\n")) }()
	if s, err := AskWithin(context.Background(), "question : ", 5*time.Second); err != nil || strings.TrimSpace(s) != "suivante" {
		t.Fatalf("réponse perdue après le délai : %q %v", s, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := AskWithin(ctx, "question : ", time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("annulation : %v", err)
	}
}

func TestPendingQuestionLeavesCredentialsFree(t *testing.T) {
	asked := make(chan struct{})
	release := make(chan struct{})
	ptm, tty, err := pty.Open()
	if err != nil {
		t.Skip(err)
	}
	defer ptm.Close()
	OpenTTY = func() (*Console, error) {
		f, err := os.OpenFile(tty.Name(), os.O_RDWR, 0)
		return &Console{In: f, Out: f}, err
	}
	Prompter = func(context.Context, *os.File, string, bool) (string, error) {
		close(asked)
		<-release
		return "o", nil
	}
	t.Cleanup(func() { OpenTTY, Prompter = openConsole, nil; tty.Close() })
	mu.Lock()
	cache["pending-test"] = Pair{User: "u", Pass: "p"}
	mu.Unlock()
	go func() { _, _ = Ask(context.Background(), "question : ") }()
	<-asked
	defer close(release)
	got := make(chan Pair, 1)
	go func() {
		p, _ := Resolve(context.Background(), "", "", "", "pending-test")
		got <- p
	}()
	select {
	case p := <-got:
		if p.Pass != "p" {
			t.Fatalf("%+v", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("identifiant en cache bloqué par une question en attente")
	}
}
