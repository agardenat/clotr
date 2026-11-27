package template

import (
	"context"

	"go.starlark.net/starlark"

	"github.com/agardenat/clotr/internal/i18n"
)

func (in *Instance) SecretRead(ctx context.Context, ref string) (string, error) {
	if !in.T.Secrets() || in.script == nil {
		return "", i18n.E("tpl.secrets.not", in.T.Name)
	}
	fn, ok := in.script.globals["read"].(starlark.Callable)
	if !ok {
		return "", i18n.E("tpl.star.secrets", in.T.Script)
	}
	if err := in.Prepare(ctx); err != nil {
		return "", err
	}
	v, err := in.call(ctx, "read", fn, starlark.String(ref))
	if err != nil {
		return "", scriptErr(err)
	}
	s, ok := starlark.AsString(v)
	if !ok {
		return "", i18n.E("tpl.secrets.result", ref, v.Type())
	}
	return s, nil
}
