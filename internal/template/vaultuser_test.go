package template

import (
	"context"
	"errors"
	"testing"

	"github.com/agardenat/clotr/internal/creds"
)

func TestVaultUser(t *testing.T) {
	calls := 0
	read := creds.ReadVault
	creds.ReadVault = func(_ context.Context, ref string) (string, error) {
		calls++
		if ref == "kv/acme/adm#username" {
			return "adm", nil
		}
		return "", errors.New("introuvable")
	}
	t.Cleanup(func() { creds.ReadVault = read })
	in := &Instance{}
	for range 2 {
		if u := in.vaultUser(context.Background(), "kv/acme/adm#private_key"); u != "adm" {
			t.Fatalf("utilisateur: %q", u)
		}
	}
	if calls != 1 {
		t.Fatalf("lectures: %d", calls)
	}
	if u := in.vaultUser(context.Background(), "kv/other"); u != "" {
		t.Fatalf("secret sans username: %q", u)
	}
}
