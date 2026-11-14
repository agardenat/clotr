package template

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/agardenat/clotr/internal/gitsync"
	"github.com/agardenat/clotr/internal/i18n"
)

func (in *Instance) SetGitRoots(roots ...string) {
	in.gitRoots = nil
	for _, r := range roots {
		if r != "" {
			in.gitRoots = append(in.gitRoots, filepath.Clean(r))
		}
	}
}

func (in *Instance) RunStartup(ctx context.Context) ([]gitsync.Result, error) {
	if !in.T.Startup() || in.script == nil {
		return nil, i18n.E("tpl.star.startup", in.T.Script)
	}
	in.mu.Lock()
	in.syncs = nil
	in.mu.Unlock()
	_, err := in.call(ctx, "startup", in.script.globals["startup"].(starlark.Callable))
	in.mu.Lock()
	defer in.mu.Unlock()
	return slices.Clone(in.syncs), scriptErrOrNil(err)
}

func scriptErrOrNil(err error) error {
	if err == nil {
		return nil
	}
	return scriptErr(err)
}

func (in *Instance) gitModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "git",
		Members: starlark.StringDict{
			"sync": starlark.NewBuiltin("git.sync", in.builtinGitSync),
		},
	}
}

func (in *Instance) builtinGitSync(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var url, dir, ref string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "url", &url, "dir", &dir, "ref?", &ref); err != nil {
		return nil, err
	}
	if thread.Local(localLoading) != nil {
		return nil, i18n.E("tpl.git.load_time")
	}
	url = strings.TrimSpace(url)
	if url == "" || strings.HasPrefix(url, "-") {
		return nil, i18n.E("tpl.git.url", url)
	}
	if strings.HasPrefix(ref, "-") {
		return nil, i18n.E("tpl.git.ref", ref)
	}
	path, err := in.gitPath(dir)
	if err != nil {
		return nil, err
	}
	r := in.gitSync(threadCtx(thread), url, path, ref)
	in.mu.Lock()
	in.syncs = append(in.syncs, r)
	in.mu.Unlock()
	in.audit("git_sync", map[string]any{"url": r.URL, "path": r.Path, "ref": r.Ref, "status": r.Status, "from": r.From, "to": r.To, "reason": r.Reason})
	return toStarlark(map[string]any{"url": r.URL, "path": r.Path, "ref": r.Ref, "status": r.Status, "from": r.From, "to": r.To, "commits": r.Commits, "reason": r.Reason, "changed": r.Changed()})
}

func (in *Instance) gitPath(dir string) (string, error) {
	if len(in.gitRoots) == 0 {
		return "", i18n.E("tpl.git.no_root")
	}
	if dir == "" || slices.Contains(strings.Split(filepath.ToSlash(dir), "/"), "..") {
		return "", i18n.E("tpl.git.dir", dir)
	}
	p := dir
	if !filepath.IsAbs(p) {
		p = filepath.Join(in.gitRoots[0], p)
	}
	p = filepath.Clean(p)
	real := in.resolveExisting(p)
	for _, root := range in.gitRoots {
		if within(real, in.resolveExisting(root)) {
			return p, nil
		}
	}
	return "", i18n.E("tpl.git.outside", dir, strings.Join(in.gitRoots, ", "))
}

func (in *Instance) resolveExisting(p string) string {
	rest := ""
	for cur := p; ; {
		r, err := in.realPath(cur)
		if err == nil {
			return filepath.Join(r, rest)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return p
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}
