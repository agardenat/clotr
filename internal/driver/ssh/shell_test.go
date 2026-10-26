//go:build !windows

package ssh

import (
	"context"
	"strings"
	"testing"
	"time"
)

const fakeGateway = `printf 'Avertissement\r\nConnexion à %s\r\nPassword: '; stty -echo; read p; stty echo; echo; [ "$p" = secret ] || { echo refusé; exit 1; }; PS1='[u@h ~]$ ' exec sh -i`

func TestShellExec(t *testing.T) {
	asked := 0
	s, err := NewShell(ShellOptions{
		Command:     []string{"sh", "-c", strings.Replace(fakeGateway, "%s", "%h", 1)},
		MaxConns:    2,
		OpenTimeout: 20 * time.Second,
		Ask: func(_ context.Context, q string) (string, error) {
			asked++
			if !strings.Contains(q, "vm1") || !strings.Contains(q, "Password:") {
				t.Errorf("question %q", q)
			}
			return "secret", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	ep := Endpoint{Host: "vm1"}
	res, err := s.ExecInput(ctx, ep, Exec([]string{"printf", "%s|%s", "a b", "c'd"}), "", 1024)
	if err != nil || res.Stdout != "a b|c'd" || res.Exit != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = s.ExecInput(ctx, ep, "echo oops >&2; echo out; exit 3", "", 1024)
	if err != nil || res.Exit != 3 || res.Stderr != "oops\n" || res.Stdout != "out\n" {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = s.ExecInput(ctx, ep, "cat", "entrée\n'x'\n", 1024)
	if err != nil || res.Stdout != "entrée\n'x'\n" {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = s.ExecInput(ctx, ep, "seq 1 20000", "", 10)
	if err != nil || res.Stdout != "1\n2\n3\n4\n5\n" || !res.Truncated {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = s.ExecInput(ctx, ep, "test -t 1 && echo tty; printf 'a\\tb\\r\\n'", "", 1024)
	if err != nil || res.Stdout != "a\tb\r\n" {
		t.Fatalf("%q %v", res.Stdout, err)
	}
	res, err = s.ExecInput(ctx, ep, "if then", "", 1024)
	if err != nil || res.Exit == 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if asked != 1 {
		t.Fatalf("questions : %d", asked)
	}
	cctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err = s.ExecInput(cctx, ep, "sleep 30", "", 1024); err == nil {
		t.Fatal("attendu : contexte expiré")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("annulation trop lente : %s", d)
	}
	res, err = s.ExecInput(ctx, ep, "echo reprise", "", 1024)
	if err != nil || res.Stdout != "reprise\n" || asked != 2 {
		t.Fatalf("%+v %v %d", res, err, asked)
	}
}

func TestShellOpenFailure(t *testing.T) {
	s, err := NewShell(ShellOptions{Command: []string{"sh", "-c", "echo 'cible %h inconnue'; exit 2"}, OpenTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.ExecInput(context.Background(), Endpoint{Host: "vm9"}, "true", "", 1024)
	if err == nil || !strings.Contains(err.Error(), "cible vm9 inconnue") {
		t.Fatalf("%v", err)
	}
	s, _ = NewShell(ShellOptions{Command: []string{"sh", "-c", "echo attente; sleep 30"}, OpenTimeout: time.Second})
	defer s.Close()
	_, err = s.ExecInput(context.Background(), Endpoint{Host: "vm9"}, "true", "", 1024)
	if err == nil || !strings.Contains(err.Error(), "attente") {
		t.Fatalf("%v", err)
	}
}
