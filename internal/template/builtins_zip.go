package template

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

const maxZipBytes = 200 << 20

var zipEpoch = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

var zipModule = &starlarkstruct.Module{
	Name: "zip",
	Members: starlark.StringDict{
		"read":  starlark.NewBuiltin("zip.read", builtinZipRead),
		"write": starlark.NewBuiltin("zip.write", builtinZipWrite),
	},
}

func builtinZipRead(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "data", &data); err != nil {
		return nil, err
	}
	raw, err := dataArg(b.Name(), data)
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", b.Name(), err)
	}
	out := starlark.NewDict(len(zr.File))
	total := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", b.Name(), f.Name, err)
		}
		content, err := io.ReadAll(io.LimitReader(rc, int64(maxZipBytes-total+1)))
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", b.Name(), f.Name, err)
		}
		if total += len(content); total > maxZipBytes {
			return nil, fmt.Errorf("%s: archive larger than %d MiB once extracted", b.Name(), maxZipBytes>>20)
		}
		_ = out.SetKey(starlark.String(f.Name), starlark.Bytes(content))
	}
	return out, nil
}

func builtinZipWrite(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var files *starlark.Dict
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "files", &files); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, it := range files.Items() {
		name, ok := starlark.AsString(it[0])
		if !ok || name == "" {
			return nil, fmt.Errorf("%s: file names must be non-empty strings", b.Name())
		}
		content, err := dataArg(b.Name(), it[1])
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", b.Name(), name, err)
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: zipEpoch})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(content); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return starlark.Bytes(buf.String()), nil
}
