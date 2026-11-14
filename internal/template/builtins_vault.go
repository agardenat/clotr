package template

import (
	"context"
	"fmt"
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/agardenat/clotr/internal/creds"
	"github.com/agardenat/clotr/internal/i18n"
)

type secretValue struct {
	ref   string
	value string
}

func (s *secretValue) String() string        { return "<secret " + s.ref + ">" }
func (s *secretValue) Type() string          { return "secret" }
func (s *secretValue) Freeze()               {}
func (s *secretValue) Truth() starlark.Bool  { return s.value != "" }
func (s *secretValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable type: secret") }

func (in *Instance) vaultModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "vault",
		Members: starlark.StringDict{
			"secret": starlark.NewBuiltin("vault.secret", in.builtinVaultSecret),
			"read":   starlark.NewBuiltin("vault.read", in.builtinVaultRead),
		},
	}
}

func (in *Instance) vaultValue(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (string, string, error) {
	var ref string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "ref", &ref); err != nil {
		return "", "", err
	}
	ref = strings.TrimSpace(ref)
	path, field, _ := strings.Cut(ref, "#")
	if path == "" || field == "" {
		return "", "", i18n.E("tpl.vault.ref", b.Name(), ref)
	}
	v, err := in.vaultRef(threadCtx(thread), threadTool(thread), ref)
	return ref, v, err
}

func (in *Instance) vaultRef(ctx context.Context, tool, ref string) (string, error) {
	if err := denyOffline(ctx); err != nil {
		return "", err
	}
	if v, ok := in.vaultCache.Load(ref); ok {
		return v.(string), nil
	}
	read := in.readVault
	if read == nil {
		read = creds.ReadVault
	}
	v, err := read(ctx, ref)
	in.audit("vault_read", map[string]any{"tool": tool, "ref": ref, "ok": err == nil})
	if err != nil {
		return "", i18n.E("tpl.vault.read", ref, err)
	}
	in.vaultCache.Store(ref, v)
	return v, nil
}

func (in *Instance) builtinVaultSecret(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	ref, v, err := in.vaultValue(thread, b, args, kwargs)
	if err != nil {
		return nil, err
	}
	return &secretValue{ref: ref, value: v}, nil
}

func (in *Instance) builtinVaultRead(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	_, v, err := in.vaultValue(thread, b, args, kwargs)
	if err != nil {
		return nil, err
	}
	return starlark.String(v), nil
}

func keyText(name string, v starlark.Value) (string, error) {
	switch x := v.(type) {
	case starlark.String:
		return string(x), nil
	case *secretValue:
		return x.value, nil
	}
	return "", fmt.Errorf("%s: key: expected string or secret, got %s", name, v.Type())
}
