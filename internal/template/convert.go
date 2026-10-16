package template

import (
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"sort"
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/agardenat/clotr/internal/i18n"
)

func toStarlark(v any) (starlark.Value, error) {
	switch x := v.(type) {
	case nil:
		return starlark.None, nil
	case starlark.Value:
		return x, nil
	case bool:
		return starlark.Bool(x), nil
	case string:
		return starlark.String(x), nil
	case []byte:
		return starlark.Bytes(x), nil
	case int:
		return starlark.MakeInt(x), nil
	case int64:
		return starlark.MakeInt64(x), nil
	case uint64:
		return starlark.MakeUint64(x), nil
	case *big.Int:
		return starlark.MakeBigInt(x), nil
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1<<53 {
			return starlark.MakeInt64(int64(x)), nil
		}
		return starlark.Float(x), nil
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return starlark.MakeInt64(i), nil
		}
		f, err := x.Float64()
		if err != nil {
			return nil, err
		}
		return starlark.Float(f), nil
	case []any:
		out := make([]starlark.Value, len(x))
		for i, e := range x {
			sv, err := toStarlark(e)
			if err != nil {
				return nil, err
			}
			out[i] = sv
		}
		return starlark.NewList(out), nil
	case []string:
		out := make([]starlark.Value, len(x))
		for i, e := range x {
			out[i] = starlark.String(e)
		}
		return starlark.NewList(out), nil
	case map[string]any:
		d := starlark.NewDict(len(x))
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sv, err := toStarlark(x[k])
			if err != nil {
				return nil, err
			}
			if err := d.SetKey(starlark.String(k), sv); err != nil {
				return nil, err
			}
		}
		return d, nil
	case []map[string]any:
		out := make([]starlark.Value, len(x))
		for i, e := range x {
			sv, err := toStarlark(e)
			if err != nil {
				return nil, err
			}
			out[i] = sv
		}
		return starlark.NewList(out), nil
	case map[string]string:
		d := starlark.NewDict(len(x))
		for _, k := range sortedKeys(x) {
			if err := d.SetKey(starlark.String(k), starlark.String(x[k])); err != nil {
				return nil, err
			}
		}
		return d, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, i18n.E("tpl.convert", v, err)
	}
	return jsonToStarlark(b)
}

func jsonToStarlark(b []byte) (starlark.Value, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return toStarlark(v)
}

func fromStarlark(v starlark.Value) (any, error) {
	switch x := v.(type) {
	case starlark.NoneType:
		return nil, nil
	case starlark.Bool:
		return bool(x), nil
	case starlark.String:
		return string(x), nil
	case starlark.Bytes:
		return string(x), nil
	case starlark.Int:
		if i, ok := x.Int64(); ok {
			return i, nil
		}
		return x.BigInt(), nil
	case starlark.Float:
		return float64(x), nil
	case *starlark.List:
		out := make([]any, x.Len())
		for i := 0; i < x.Len(); i++ {
			e, err := fromStarlark(x.Index(i))
			if err != nil {
				return nil, err
			}
			out[i] = e
		}
		return out, nil
	case starlark.Tuple:
		out := make([]any, len(x))
		for i, e := range x {
			g, err := fromStarlark(e)
			if err != nil {
				return nil, err
			}
			out[i] = g
		}
		return out, nil
	case *starlark.Dict:
		out := make(map[string]any, x.Len())
		for _, it := range x.Items() {
			k, ok := starlark.AsString(it[0])
			if !ok {
				return nil, i18n.E("tpl.dict_key", it[0].Type())
			}
			e, err := fromStarlark(it[1])
			if err != nil {
				return nil, err
			}
			out[k] = e
		}
		return out, nil
	case *starlarkstruct.Struct:
		d := starlark.StringDict{}
		x.ToStringDict(d)
		out := make(map[string]any, len(d))
		for k, e := range d {
			if _, ok := e.(starlark.Callable); ok {
				continue
			}
			g, err := fromStarlark(e)
			if err != nil {
				return nil, err
			}
			out[k] = g
		}
		return out, nil
	}
	return v.String(), nil
}

func starlarkJSON(v starlark.Value) ([]byte, error) {
	g, err := fromStarlark(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(g)
}

func decodeStarlark(v starlark.Value, out any) error {
	b, err := starlarkJSON(v)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func scriptErr(err error) error {
	var ee *starlark.EvalError
	if errors.As(err, &ee) {
		return errors.New(strings.TrimPrefix(ee.Msg, "fail: "))
	}
	return err
}

func scriptTrace(err error) string {
	var ee *starlark.EvalError
	if errors.As(err, &ee) {
		return ee.Backtrace()
	}
	return err.Error()
}

func makeStruct(fields map[string]any) (*starlarkstruct.Struct, error) {
	d := starlark.StringDict{}
	for k, v := range fields {
		sv, err := toStarlark(v)
		if err != nil {
			return nil, err
		}
		d[k] = sv
	}
	return starlarkstruct.FromStringDict(starlarkstruct.Default, d), nil
}
