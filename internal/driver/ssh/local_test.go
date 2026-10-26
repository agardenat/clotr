package ssh

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestLocalExec(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh requis")
	}
	l := NewLocal(2)
	defer l.Close()
	ctx := context.Background()
	res, err := l.ExecInput(ctx, Endpoint{}, Exec([]string{"printf", "%s|%s", "a b", "c'd"}), "", 1024)
	if err != nil || res.Stdout != "a b|c'd" || res.Exit != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = l.ExecInput(ctx, Endpoint{}, "echo oops >&2; exit 3", "", 1024)
	if err != nil || res.Exit != 3 || res.Stderr != "oops\n" {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = l.ExecInput(ctx, Endpoint{}, "cat", "entrée\n", 1024)
	if err != nil || res.Stdout != "entrée\n" {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = l.ExecInput(ctx, Endpoint{}, "printf 0123456789", "", 4)
	if err != nil || res.Stdout != "0123" || !res.Truncated {
		t.Fatalf("%+v %v", res, err)
	}
	cctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err = l.ExecInput(cctx, Endpoint{}, "sleep 30 | cat", "", 1024); err == nil {
		t.Fatal("attendu : contexte expiré")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("annulation trop lente : %s", d)
	}
}
