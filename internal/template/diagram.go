package template

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"go.starlark.net/starlark"

	"github.com/agardenat/clotr/internal/i18n"
)

type DiagramResult struct {
	Drawio   []byte
	PNG      []byte
	Warnings []string
	Notes    []string
}

func (in *Instance) diagramFn(name string) (starlark.Callable, error) {
	if !in.T.Diagram() || in.script == nil {
		return nil, i18n.E("diagram.not", in.T.Name)
	}
	fn, ok := in.script.globals[name].(starlark.Callable)
	if !ok {
		return nil, i18n.E("diagram.fn", in.T.Script, name)
	}
	return fn, nil
}

func (in *Instance) diagramText(ctx context.Context, name string, args ...starlark.Value) (string, error) {
	fn, err := in.diagramFn(name)
	if err != nil {
		return "", err
	}
	v, err := in.call(ctx, name, fn, args...)
	if err != nil {
		return "", scriptErr(err)
	}
	switch t := v.(type) {
	case starlark.String:
		return string(t), nil
	case starlark.Bytes:
		return string(t), nil
	}
	g, err := fromStarlark(v)
	if err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(g, "", " ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (in *Instance) DiagramReference(ctx context.Context, cloud string) (string, error) {
	return in.diagramText(ctx, "reference", starlark.String(cloud))
}

func (in *Instance) DiagramShapes(ctx context.Context, query, cloud string) (string, error) {
	return in.diagramText(ctx, "shapes", starlark.String(query), starlark.String(cloud))
}

func (in *Instance) DiagramRender(ctx context.Context, cloud string, spec map[string]any) (*DiagramResult, error) {
	fn, err := in.diagramFn("render")
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	arg, err := jsonToStarlark(raw)
	if err != nil {
		return nil, err
	}
	v, err := in.call(ctx, "render", fn, arg, starlark.String(cloud))
	if err != nil {
		return nil, scriptErr(err)
	}
	return decodeDiagram(v)
}

func decodeDiagram(v starlark.Value) (*DiagramResult, error) {
	field := func(name string) (starlark.Value, error) {
		switch t := v.(type) {
		case *starlark.Dict:
			x, _, err := t.Get(starlark.String(name))
			return x, err
		case starlark.HasAttrs:
			x, err := t.Attr(name)
			if err != nil {
				return nil, nil
			}
			return x, nil
		}
		return nil, i18n.E("diagram.result", "render", v.Type())
	}
	bytesOf := func(name string) ([]byte, error) {
		x, err := field(name)
		if err != nil {
			return nil, err
		}
		switch t := x.(type) {
		case nil, starlark.NoneType:
			return nil, nil
		case starlark.Bytes:
			return []byte(string(t)), nil
		case starlark.String:
			s := string(t)
			if name == "png" {
				b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
				if err != nil {
					return nil, i18n.E("diagram.result", "render.png", err)
				}
				return b, nil
			}
			return []byte(s), nil
		}
		return nil, i18n.E("diagram.result", "render."+name, x.Type())
	}
	r := &DiagramResult{}
	var err error
	if r.Drawio, err = bytesOf("drawio"); err != nil {
		return nil, err
	}
	if r.PNG, err = bytesOf("png"); err != nil {
		return nil, err
	}
	strs := func(name string) ([]string, error) {
		w, err := field(name)
		if err != nil || w == nil || w == starlark.None {
			return nil, err
		}
		g, err := fromStarlark(w)
		if err != nil {
			return nil, err
		}
		list, ok := g.([]any)
		if !ok {
			return nil, i18n.E("diagram.result", "render."+name, w.Type())
		}
		var out []string
		for _, x := range list {
			if s := strings.TrimSpace(fmt.Sprint(x)); s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	}
	if r.Warnings, err = strs("warnings"); err != nil {
		return nil, err
	}
	if r.Notes, err = strs("notes"); err != nil {
		return nil, err
	}
	return r, nil
}
