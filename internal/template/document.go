package template

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/agardenat/clotr/internal/i18n"
)

const KindDocument = "document"

const maxAssetBytes = 100 << 20

var documentPredeclared = []string{"json", "time", "math", "base64", "sprintf", "struct", "re", "yaml", "catch", "compact_json", "jq", "xml", "zip", "markdown", "asset"}

func (t *Template) Document() bool {
	return t.Kind == KindDocument
}

func (in *Instance) documentPredeclared() starlark.StringDict {
	base := in.basePredeclared()
	d := starlark.StringDict{
		"xml":      xmlModule,
		"zip":      zipModule,
		"markdown": markdownModule,
		"asset":    starlark.NewBuiltin("asset", in.builtinAsset),
	}
	for _, n := range documentPredeclared {
		if v, ok := base[n]; ok {
			d[n] = v
		}
	}
	return d
}

func (in *Instance) builtinAsset(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	if name == "" || name != filepath.Base(name) || strings.HasPrefix(name, ".") {
		return nil, i18n.E("tpl.doc.asset_name", name)
	}
	p := filepath.Join(filepath.Dir(in.T.Source), name)
	st, err := os.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("asset: %w", err)
	}
	if !st.Mode().IsRegular() || st.Size() > maxAssetBytes {
		return nil, i18n.E("tpl.doc.asset_file", name)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("asset: %w", err)
	}
	return starlark.Bytes(data), nil
}

type DocumentInput struct {
	Markdown string
	Title    string
	Mode     string
	Language string
	Request  string
	Ticket   string
	Date     string
	Session  string
}

func (d DocumentInput) value(params map[string]any) (starlark.Value, error) {
	p, err := toStarlark(params)
	if err != nil {
		return nil, err
	}
	return starlarkstruct.FromStringDict(starlark.String("document"), starlark.StringDict{
		"markdown": starlark.String(d.Markdown),
		"title":    starlark.String(d.Title),
		"mode":     starlark.String(d.Mode),
		"language": starlark.String(d.Language),
		"request":  starlark.String(d.Request),
		"ticket":   starlark.String(d.Ticket),
		"date":     starlark.String(d.Date),
		"session":  starlark.String(d.Session),
		"params":   p,
	}), nil
}

func (in *Instance) RenderDocument(ctx context.Context, doc DocumentInput) ([]byte, error) {
	if !in.T.Document() || in.script == nil {
		return nil, i18n.E("tpl.doc.not", in.T.Name)
	}
	arg, err := doc.value(in.params)
	if err != nil {
		return nil, err
	}
	v, err := in.call(ctx, "render", in.script.globals["render"].(starlark.Callable), arg)
	if err != nil {
		return nil, scriptErr(err)
	}
	switch t := v.(type) {
	case starlark.Bytes:
		return []byte(string(t)), nil
	case starlark.String:
		return []byte(string(t)), nil
	}
	return nil, i18n.E("tpl.doc.result", in.T.Script, v.Type())
}

func documentName(name string) bool {
	return slices.Contains(documentPredeclared, name)
}
