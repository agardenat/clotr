package creds

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestResolveVault(t *testing.T) {
	calls := 0
	readVault := ReadVault
	ReadVault = func(_ context.Context, ref string) (string, error) {
		calls++
		if ref != "kv/ops#password" {
			return "", errors.New("introuvable")
		}
		return "fromvault", nil
	}
	OpenTTY = func() (*Console, error) { return nil, errors.New("pas de terminal") }
	t.Cleanup(func() { ReadVault, OpenTTY = readVault, openConsole })
	ctx := context.Background()

	p, err := ResolveUser(ctx, "ops", "", "kv/ops#password", "lab (SSH)")
	if err != nil || p.Pass != "fromvault" {
		t.Fatalf("Vault: %+v %v", p, err)
	}
	if p, err = ResolveUser(ctx, "ops", "", "kv/ops#password", "lab (SSH)"); err != nil || p.Pass != "fromvault" || calls != 1 {
		t.Fatalf("cache: %+v %v %d", p, err, calls)
	}
	t.Setenv("LAB_PW", "fromenv")
	if p, err = ResolveUser(ctx, "ops", "LAB_PW", "kv/ops#password", "lab (API)"); err != nil || p.Pass != "fromenv" || calls != 1 {
		t.Fatalf("variable prioritaire: %+v %v %d", p, err, calls)
	}

	Forget("lab (SSH)", "ops")
	if _, err = ResolveUser(ctx, "ops", "", "kv/ops#password", "lab (SSH)"); err == nil || calls != 1 {
		t.Fatalf("mot de passe Vault refusé puis relu: %v %d", err, calls)
	}

	_, err = ResolveUser(ctx, "ops", "", "kv/other", "lab (CM)")
	if err == nil || !strings.Contains(err.Error(), "Vault kv/other : introuvable") {
		t.Fatalf("échec Vault non signalé: %v", err)
	}
}
