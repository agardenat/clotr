package creds

import (
	"context"
	"strings"
	"sync"

	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/vault"
)

const VaultSource = "vault"

type SecretSource func(ctx context.Context, ref string) (string, error)

var (
	sourcesMu    sync.Mutex
	sources      = map[string]SecretSource{}
	sourceErrs   = map[string]error{}
	secretValues = map[string]string{}
)

type sourceKey struct{}

func RegisterSecretSource(name string, fn SecretSource) {
	sourcesMu.Lock()
	defer sourcesMu.Unlock()
	sources[name] = fn
	delete(sourceErrs, name)
}

func DisableSecretSource(name string, err error) {
	sourcesMu.Lock()
	defer sourcesMu.Unlock()
	delete(sources, name)
	sourceErrs[name] = err
}

func ResetSecretSources() {
	sourcesMu.Lock()
	defer sourcesMu.Unlock()
	sources = map[string]SecretSource{}
	sourceErrs = map[string]error{}
	secretValues = map[string]string{}
}

func SplitSource(ref string) (name, rest string, ok bool) {
	name, rest, found := strings.Cut(ref, ":")
	if !found || name == "" {
		return "", ref, false
	}
	if name == VaultSource {
		return name, rest, true
	}
	sourcesMu.Lock()
	defer sourcesMu.Unlock()
	if _, known := sources[name]; known {
		return name, rest, true
	}
	if _, known := sourceErrs[name]; known {
		return name, rest, true
	}
	return "", ref, false
}

func InSource(ctx context.Context) bool {
	_, ok := ctx.Value(sourceKey{}).([]string)
	return ok
}

func resolveInSource(ctx context.Context, p Pair, userVault, passVault, label string, secretOnly bool) (Pair, error) {
	if p.User == "" && !secretOnly && userVault != "" {
		v, err := ReadVault(ctx, userVault)
		if err != nil {
			return Pair{}, i18n.E("creds.source_creds_read", label, userVault, err)
		}
		p.User = v
	}
	if p.Pass == "" && passVault != "" {
		v, err := ReadVault(ctx, passVault)
		if err != nil {
			return Pair{}, i18n.E("creds.source_creds_read", label, passVault, err)
		}
		p.Pass = v
	}
	if p.User == "" && !secretOnly && passVault != "" {
		p.User, _ = ReadVaultUser(ctx, passVault)
	}
	if p.Pass == "" || p.User == "" && !secretOnly {
		return Pair{}, i18n.E("creds.source_creds", label)
	}
	return p, nil
}

func readSecret(ctx context.Context, ref string) (string, error) {
	name, rest, ok := SplitSource(ref)
	if !ok || name == VaultSource {
		return vault.Secret(ctx, rest)
	}
	sourcesMu.Lock()
	if v, cached := secretValues[ref]; cached {
		sourcesMu.Unlock()
		return v, nil
	}
	fn, err := sources[name], sourceErrs[name]
	sourcesMu.Unlock()
	if fn == nil {
		return "", i18n.E("creds.source_down", name, err)
	}
	chain, _ := ctx.Value(sourceKey{}).([]string)
	for _, n := range chain {
		if n == name {
			return "", i18n.E("creds.source_loop", strings.Join(append(chain, name), " → "))
		}
	}
	v, err := fn(context.WithValue(ctx, sourceKey{}, append(append([]string(nil), chain...), name)), rest)
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", i18n.E("creds.source_empty", name, rest)
	}
	sourcesMu.Lock()
	secretValues[ref] = v
	sourcesMu.Unlock()
	return v, nil
}
