package template

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/i18n"
)

const (
	dirSuffix      = "/**"
	defaultListMax = 5000
)

type dirEntry struct {
	path, kind, target string
	size               int64
}

func splitFiles(rendered []string) (files, dirs []string, err error) {
	for _, f := range rendered {
		d, isDir := strings.CutSuffix(f, dirSuffix)
		if !isDir {
			files = append(files, f)
			continue
		}
		d = filepath.Clean(config.ExpandHome(d))
		if !filepath.IsAbs(d) || d == string(filepath.Separator) {
			return nil, nil, i18n.E("tpl.file_dir", f)
		}
		dirs = append(dirs, d)
	}
	return files, dirs, nil
}

func within(p, root string) bool {
	return p == root || strings.HasPrefix(p, strings.TrimSuffix(root, string(filepath.Separator))+string(filepath.Separator))
}

func (in *Instance) fileAllowed(p string) (string, error) {
	want := config.ExpandHome(p)
	for _, f := range in.files {
		if config.ExpandHome(f) == want {
			return want, nil
		}
	}
	want = filepath.Clean(want)
	for _, d := range in.dirs {
		if !within(want, d) {
			continue
		}
		real, err := in.realPath(want)
		if err != nil {
			return "", err
		}
		root, err := in.realPath(d)
		if err != nil {
			return "", err
		}
		if !within(real, root) {
			return "", i18n.E("tpl.file_outside", p, d)
		}
		return want, nil
	}
	return "", i18n.E("tpl.file_undeclared", p)
}

func walkDir(root string, depth, limit int) ([]dirEntry, bool, error) {
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, false, err
	}
	var out []dirEntry
	truncated := false
	base := strings.Count(real, string(filepath.Separator))
	err = filepath.WalkDir(real, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == real {
				return err
			}
			return nil
		}
		if p == real {
			return nil
		}
		if strings.Count(p, string(filepath.Separator))-base > depth {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if len(out) >= limit {
			truncated = true
			return fs.SkipAll
		}
		rel, _ := filepath.Rel(real, p)
		e := dirEntry{path: filepath.Join(root, rel), kind: "file"}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			e.kind = "link"
			e.target, _ = os.Readlink(p)
		case d.IsDir():
			e.kind = "dir"
		default:
			if info, err := d.Info(); err == nil {
				e.size = info.Size()
			}
		}
		out = append(out, e)
		return nil
	})
	if err != nil && !errors.Is(err, fs.SkipAll) {
		return nil, false, err
	}
	return out, truncated, nil
}

func (in *Instance) fileModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "file",
		Members: starlark.StringDict{
			"read": starlark.NewBuiltin("file.read", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var p string
				if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &p); err != nil {
					return nil, err
				}
				full, err := in.fileAllowed(p)
				if err != nil {
					return nil, err
				}
				data, err := in.readFile(full)
				if err != nil {
					return nil, fmt.Errorf("file.read %s: %w", p, err)
				}
				return starlark.String(data), nil
			}),
			"exists": starlark.NewBuiltin("file.exists", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var p string
				if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &p); err != nil {
					return nil, err
				}
				full, err := in.fileAllowed(p)
				if errors.Is(err, fs.ErrNotExist) {
					return starlark.False, nil
				}
				if err != nil {
					return nil, err
				}
				_, err = in.readFile(full)
				return starlark.Bool(err == nil), nil
			}),
			"list": starlark.NewBuiltin("file.list", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var p string
				depth, limit := 1, defaultListMax
				if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &p, "depth?", &depth, "max?", &limit); err != nil {
					return nil, err
				}
				full, err := in.fileAllowed(p)
				if err != nil {
					return nil, err
				}
				if !in.isDirAllowed(full) {
					return nil, i18n.E("tpl.file_list_dir", p)
				}
				entries, truncated, err := in.listDir(full, max(depth, 1), max(limit, 1))
				if err != nil {
					return nil, fmt.Errorf("file.list %s: %w", p, err)
				}
				items := make([]any, len(entries))
				for i, e := range entries {
					items[i] = map[string]any{"path": e.path, "type": e.kind, "size": e.size, "target": e.target}
				}
				return makeStruct(map[string]any{"entries": items, "truncated": truncated})
			}),
		},
	}
}

func (in *Instance) isDirAllowed(p string) bool {
	for _, d := range in.dirs {
		if within(p, d) {
			return true
		}
	}
	return false
}
