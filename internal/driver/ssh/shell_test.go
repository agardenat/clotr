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

func TestShellShortHost(t *testing.T) {
	s, err := NewShell(ShellOptions{Command: []string{"sh", "-c", "echo 'cible %s sur %h'; exit 2"}, OpenTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.ExecInput(context.Background(), Endpoint{Host: "vm9.example.test"}, "true", "", 1024)
	if err == nil || !strings.Contains(err.Error(), "cible vm9 sur vm9.example.test") {
		t.Fatalf("%v", err)
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

func TestShellThen(t *testing.T) {
	var questions []string
	s, err := NewShell(ShellOptions{
		Command:     []string{"sh", "-c", "PS1='[u@jump ~]$ ' exec sh -i"},
		Then:        []string{`exec env HOP=%s sh -c 'printf "%h password: "; stty -echo; read p; stty echo; echo; [ "$p" = deux ] || exit 1; PS1="[u@vm ~]$ " exec sh -i'`},
		OpenTimeout: 20 * time.Second,
		Ask: func(_ context.Context, q string) (string, error) {
			questions = append(questions, q)
			return "deux", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	res, err := s.ExecInput(context.Background(), Endpoint{Host: "vm1.example.test"}, "echo $HOP", "", 1024)
	if err != nil || res.Stdout != "vm1\n" {
		t.Fatalf("%+v %v", res, err)
	}
	if len(questions) != 1 || !strings.Contains(questions[0], "vm1.example.test password:") {
		t.Fatalf("%q", questions)
	}
}

func TestShellThenFailure(t *testing.T) {
	s, err := NewShell(ShellOptions{
		Command:     []string{"sh", "-c", "PS1='[u@jump ~]$ ' exec sh -i"},
		Then:        []string{`exec sh -c 'echo "ssh: Could not resolve hostname %h"; exit 255'`},
		OpenTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.ExecInput(context.Background(), Endpoint{Host: "vm9"}, "echo jump", "", 1024)
	if err == nil || !strings.Contains(err.Error(), "Could not resolve hostname vm9") {
		t.Fatalf("%v", err)
	}
}

func TestShellThenLogin(t *testing.T) {
	hop := `exec sh -c 'while :; do printf "%u@%h password: "; stty -echo; read p; stty echo; echo; [ "$p" = deux ] && break; echo "Permission denied, please try again."; done; HOP=%u@%s PS1="[u@vm ~]$ " exec sh -i'`
	pass, logins, forgot := "deux", 0, ""
	s, err := NewShell(ShellOptions{
		Command:     []string{"sh", "-c", "PS1='[u@jump ~]$ ' exec sh -i"},
		Then:        []string{hop},
		OpenTimeout: 20 * time.Second,
		Ask: func(context.Context, string) (string, error) {
			t.Error("question relayée au lieu des identifiants")
			return "", nil
		},
		Login: func(context.Context) (string, string, error) {
			logins++
			return "ops", pass, nil
		},
		Forget: func(user string) { forgot = user },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	res, err := s.ExecInput(context.Background(), Endpoint{Host: "vm1.example.test"}, "echo $HOP", "", 1024)
	if err != nil || res.Stdout != "ops@vm1\n" || forgot != "" {
		t.Fatalf("%+v %v %q", res, err, forgot)
	}
	pass = "faux"
	_, err = s.ExecInput(context.Background(), Endpoint{Host: "vm2"}, "true", "", 1024)
	if err == nil || !strings.Contains(err.Error(), "Permission denied") || forgot != "ops" {
		t.Fatalf("%v %q", err, forgot)
	}
	if logins != 4 {
		t.Fatalf("appels Login : %d", logins)
	}
}
