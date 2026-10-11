package template

import (
	"bytes"
	"encoding/json"
	"fmt"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"gopkg.in/yaml.v3"
)

var yamlModule = &starlarkstruct.Module{
	Name: "yaml",
	Members: starlark.StringDict{
		"decode": starlark.NewBuiltin("yaml.decode", builtinYAMLDecode),
		"encode": starlark.NewBuiltin("yaml.encode", builtinYAMLEncode),
	},
}

func builtinYAMLDecode(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &text); err != nil {
		return nil, err
	}
	var v any
	if err := yaml.Unmarshal([]byte(text), &v); err != nil {
		return nil, fmt.Errorf("yaml.decode: %w", err)
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("yaml.decode: %w", err)
	}
	return jsonToStarlark(data)
}

func builtinYAMLEncode(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var v starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "value", &v); err != nil {
		return nil, err
	}
	g, err := fromStarlark(v)
	if err != nil {
		return nil, fmt.Errorf("yaml.encode: %w", err)
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(g); err != nil {
		return nil, fmt.Errorf("yaml.encode: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("yaml.encode: %w", err)
	}
	return starlark.String(buf.String()), nil
}
