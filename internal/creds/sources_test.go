package creds

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func withSources(t *testing.T) {
	t.Helper()
	readVault := ReadVault
	ReadVault = readSecret
	OpenTTY = func() (*Console, error) { return nil, errors.New("pas de terminal") }
	ResetSecretSources()
	t.Setenv("VAULT_ADDR", "")
	t.Cleanup(func() {
		ReadVault, OpenTTY = readVault, openConsole
		ResetSecretSources()
	})
}

func TestSecretSourceDispatch(t *testing.T) {
	withSources(t)
	calls := 0
	RegisterSecretSource("store", func(_ context.Context, ref string) (string, error) {
		calls++
		switch ref {
		case "1234#password":
			return "s3cret", nil
		case "1234#username":
			return "svc", nil
		}
		return "", errors.New("absent")
	})
	ctx := context.Background()
	if v, err := ReadVault(ctx, "store:1234#password"); err != nil || v != "s3cret" {
		t.Fatalf("lecture: %q %v", v, err)
	}
	if _, err := ReadVault(ctx, "store:1234#password"); err != nil || calls != 1 {
		t.Fatalf("cache: %v %d", err, calls)
	}
	p, err := Resolve(ctx, "", "", "store:1234#password", "app (API)")
	if err != nil || p.User != "svc" || p.Pass != "s3cret" {
		t.Fatalf("compte déduit de #username: %+v %v", p, err)
	}
	if _, err := ReadVault(ctx, "store:1#password"); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("erreur de la source: %v", err)
	}
	if _, err := ReadVault(ctx, "kv/ops:x#password"); err == nil || !strings.Contains(err.Error(), "VAULT_ADDR") {
		t.Fatalf("préfixe inconnu envoyé à Vault: %v", err)
	}
	if _, err := ReadVault(ctx, "vault:kv/ops#password"); err == nil || !strings.Contains(err.Error(), "VAULT_ADDR") {
		t.Fatalf("préfixe vault explicite: %v", err)
	}
}

func TestSecretSourceDisabled(t *testing.T) {
	withSources(t)
	DisableSecretSource("store", errors.New("template absent"))
	_, err := ReadVault(context.Background(), "store:1#password")
	if err == nil || !strings.Contains(err.Error(), "store") || !strings.Contains(err.Error(), "template absent") {
		t.Fatalf("source indisponible: %v", err)
	}
}

func TestSecretSourceLoop(t *testing.T) {
	withSources(t)
	RegisterSecretSource("a", func(ctx context.Context, _ string) (string, error) {
		return ReadVault(ctx, "b:x")
	})
	RegisterSecretSource("b", func(ctx context.Context, _ string) (string, error) {
		return ReadVault(ctx, "a:x")
	})
	_, err := ReadVault(context.Background(), "a:x")
	if err == nil || !strings.Contains(err.Error(), "a → b → a") {
		t.Fatalf("boucle non détectée: %v", err)
	}
}

func TestSecretSourceOwnCredentialsNoDeadlock(t *testing.T) {
	withSources(t)
	RegisterSecretSource("base", func(_ context.Context, ref string) (string, error) {
		if ref == "login#username" {
			return "data", nil
		}
		return "pw", nil
	})
	RegisterSecretSource("store", func(ctx context.Context, ref string) (string, error) {
		p, err := ResolveUser(ctx, "data", "", "base:login#password", "store (proxy)")
		if err != nil {
			return "", err
		}
		if _, err := Resolve(ctx, "", "", "base:login#password", "store (API)"); err != nil {
			return "", err
		}
		if _, err := Resolve(ctx, "", "", "", "store (sans source)"); err == nil {
			return "", errors.New("saisie attendue refusée")
		}
		return p.User + "/" + ref, nil
	})
	done := make(chan error, 1)
	go func() {
		p, err := Resolve(context.Background(), "", "", "store:9#password", "web (API)")
		if err == nil && p.Pass != "data/9#password" {
			err = errors.New(p.Pass)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("interblocage : la source attend le verrou tenu par resolve")
	}
}

func TestResolveUserReference(t *testing.T) {
	withSources(t)
	RegisterSecretSource("store", func(_ context.Context, ref string) (string, error) {
		switch ref {
		case "1234#user":
			return "svc_app", nil
		case "1234#password":
			return "pw", nil
		}
		return "", errors.New("champ " + ref + " absent")
	})
	ctx := context.Background()
	p, err := ResolveRefs(ctx, "", "store:1234#user", "", "store:1234#password", "app-x (API)")
	if err != nil || p.User != "svc_app" || p.Pass != "pw" {
		t.Fatalf("compte par référence: %+v %v", p, err)
	}
	t.Setenv("APP_X_USER", "fromenv")
	if p, err = ResolveRefs(ctx, "APP_X_USER", "store:1234#user", "", "store:1234#password", "app-y (API)"); err != nil || p.User != "fromenv" {
		t.Fatalf("variable prioritaire sur la référence: %+v %v", p, err)
	}
	_, err = ResolveRefs(ctx, "", "store:1234#login", "", "store:1234#password", "app-z (API)")
	if err == nil || !strings.Contains(err.Error(), "store:1234#login") {
		t.Fatalf("référence de compte illisible non signalée: %v", err)
	}
}
