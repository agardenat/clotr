//go:build !windows

package creds

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/creack/pty"
)

func TestVaultStore(t *testing.T) {
	ptm, tty, err := pty.Open()
	if err != nil {
		t.Skip(err)
	}
	defer ptm.Close()
	var smu sync.Mutex
	saved := map[string]map[string]string{}
	read, write, del := storeRead, storeWrite, storeDelete
	storeRead = func(_ context.Context, path string) (map[string]string, error) {
		smu.Lock()
		defer smu.Unlock()
		return saved[path], nil
	}
	storeWrite = func(_ context.Context, path string, d map[string]string) error {
		smu.Lock()
		defer smu.Unlock()
		saved[path] = d
		return nil
	}
	storeDelete = func(_ context.Context, path string) error {
		smu.Lock()
		defer smu.Unlock()
		delete(saved, path)
		return nil
	}
	OpenTTY = func() (*Console, error) {
		f, err := os.OpenFile(tty.Name(), os.O_RDWR, 0)
		return &Console{In: f, Out: f}, err
	}
	asked := 0
	Prompter = func(_ context.Context, _ *os.File, _ string, secret bool) (string, error) {
		asked++
		if secret {
			return "pw1", nil
		}
		return "alice\n", nil
	}
	UseVaultStore("cubbyhole/clotr/")
	t.Cleanup(func() {
		storeRead, storeWrite, storeDelete = read, write, del
		OpenTTY, Prompter = openConsole, nil
		UseVaultStore("")
		tty.Close()
	})
	reset := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, m := range []map[string]Pair{cache} {
			for k := range m {
				delete(m, k)
			}
		}
		for k := range skipVault {
			delete(skipVault, k)
		}
	}
	ctx := context.Background()
	label := "ssh acme (Bastion) é"
	path := "cubbyhole/clotr/ssh-acme-bastion"

	p, err := Resolve(ctx, "", "", "", label)
	if err != nil || p.User != "alice" || p.Pass != "pw1" || asked != 2 {
		t.Fatalf("saisie : %+v %v %d", p, err, asked)
	}
	if d := saved[path]; d["username"] != "alice" || d["password"] != "pw1" || d["label"] != label {
		t.Fatalf("non enregistré : %v", saved)
	}

	reset()
	if p, err = Resolve(ctx, "", "", "", label); err != nil || p.User != "alice" || p.Pass != "pw1" || asked != 2 {
		t.Fatalf("relu du cache sans saisie : %+v %v %d", p, err, asked)
	}

	reset()
	if p, err = ResolveUser(ctx, "bob", "", "", label); err != nil || p.User != "bob" || asked != 3 {
		t.Fatalf("autre compte imposé : %+v %v %d", p, err, asked)
	}

	reset()
	saved[path]["label"] = "autre"
	if _, err = Resolve(ctx, "", "", "", label); err != nil || asked != 5 {
		t.Fatalf("libellé différent ignoré : %v %d", err, asked)
	}

	Reject(label, "alice", "pw1", "refusé")
	if _, ok := saved[path]; ok {
		t.Fatalf("identifiants refusés gardés : %v", saved)
	}
	Prompter = func(_ context.Context, _ *os.File, _ string, secret bool) (string, error) {
		asked++
		if secret {
			return "pw2", nil
		}
		return "\n", nil
	}
	if p, err = Resolve(ctx, "", "", "", label); err != nil || p.Pass != "pw2" || saved[path]["password"] != "pw2" {
		t.Fatalf("nouvelle saisie enregistrée : %+v %v %v", p, err, saved)
	}

	reset()
	UseVaultStore("")
	if _, err = ResolveSecret(ctx, "", "", "jeton"); err != nil || len(saved) != 1 {
		t.Fatalf("sans cache configuré : %v %v", err, saved)
	}
}
