package ssh

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestFollowLocal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh requis")
	}
	l := NewLocal(1)
	ctx := context.Background()
	f := filepath.Join(t.TempDir(), "a b.log")
	if err := os.WriteFile(f, []byte("un\ndeux\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := l.ExecInput(ctx, Endpoint{}, Builder{}.Follow(f, 3, 1<<20), "", 1<<20)
	head, data, _ := strings.Cut(res.Stdout, "\n")
	if err != nil || res.Exit != 0 || !strings.HasPrefix(head, "8 ") || data != "deux\n" {
		t.Fatalf("%+v %v", res, err)
	}
	res, _ = l.ExecInput(ctx, Endpoint{}, Builder{}.Follow(f, 0, 4), "", 1<<20)
	if _, data, _ = strings.Cut(res.Stdout, "\n"); data != "un\nd" {
		t.Fatalf("plafond : %q", res.Stdout)
	}
	res, _ = l.ExecInput(ctx, Endpoint{}, Builder{}.Follow(f, 8, 4), "", 1<<20)
	if _, data, _ = strings.Cut(res.Stdout, "\n"); data != "" || res.Exit != 0 {
		t.Fatalf("rien de neuf : %+v", res)
	}
	res, _ = l.ExecInput(ctx, Endpoint{}, Builder{}.Follow(f, 20, 4), "", 1<<20)
	if !strings.HasPrefix(res.Stdout, "8 ") || res.Exit != 0 {
		t.Fatalf("fichier raccourci : %+v", res)
	}
	res, _ = l.ExecInput(ctx, Endpoint{}, Builder{}.Follow(f+".absent", 0, 4), "", 1<<20)
	if res.Exit == 0 {
		t.Fatalf("fichier absent : %+v", res)
	}
}
