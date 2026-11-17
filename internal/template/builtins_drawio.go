package template

import (
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/agardenat/clotr/internal/drawio"
)

var drawioModule = &starlarkstruct.Module{
	Name: "drawio",
	Members: starlark.StringDict{
		"route": starlark.NewBuiltin("drawio.route", builtinDrawioRoute),
		"png":   starlark.NewBuiltin("drawio.png", builtinDrawioPNG),
	},
}

func builtinDrawioRoute(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data starlark.Value
	spreadX, spreadY := starlark.Float(1), starlark.Float(1)
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "xml", &data, "spread_x?", &spreadX, "spread_y?", &spreadY); err != nil {
		return nil, err
	}
	raw, err := dataArg(b.Name(), data)
	if err != nil {
		return nil, err
	}
	out, res, err := drawio.Route(raw, drawio.Options{SpreadX: float64(spreadX), SpreadY: float64(spreadY)})
	if err != nil {
		return nil, err
	}
	failed := make([]starlark.Value, len(res.Failed))
	for i, f := range res.Failed {
		failed[i] = starlark.String(f)
	}
	return starlarkstruct.FromStringDict(starlark.String("route"), starlark.StringDict{
		"xml":    starlark.String(out),
		"edges":  starlark.MakeInt(res.Edges),
		"failed": starlark.NewList(failed),
	}), nil
}

func builtinDrawioPNG(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data starlark.Value
	scale := starlark.Float(2)
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "xml", &data, "scale?", &scale); err != nil {
		return nil, err
	}
	raw, err := dataArg(b.Name(), data)
	if err != nil {
		return nil, err
	}
	png, err := drawio.PNG(raw, float64(scale))
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(png), nil
}
