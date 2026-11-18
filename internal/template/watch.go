package template

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"go.starlark.net/starlark"

	"github.com/agardenat/clotr/internal/access"
	"github.com/agardenat/clotr/internal/driver/ssh"
	"github.com/agardenat/clotr/internal/i18n"
)

type WatchHost struct {
	in *Instance
	t  *Target
	h  *Host
}

func (in *Instance) Watchable() bool {
	return in.sshName != "" && in.offered().Allows(access.Read)
}

func (in *Instance) WatchHost(target, host string) (*WatchHost, error) {
	if !in.Watchable() {
		return nil, i18n.E("tpl.ssh.no_connector", in.T.Name)
	}
	if err := in.ensure(); err != nil {
		return nil, err
	}
	t, h, err := in.findHost(target, host)
	if err != nil {
		return nil, err
	}
	return &WatchHost{in: in, t: t, h: h}, nil
}

func (in *Instance) WatchPath(p string) (string, error) {
	if in.rules == nil {
		return "", i18n.E("tpl.ssh.no_connector", in.T.Name)
	}
	return in.rules.Check(p)
}

func (w *WatchHost) Name() string {
	if w.h.Name != "" {
		return w.h.Name
	}
	return w.h.IP
}

func (w *WatchHost) Target() string { return w.t.Name }

func (w *WatchHost) Run(ctx context.Context, tool string, cmd func(ssh.Builder) string, maxBytes int) (ssh.Result, error) {
	return w.in.remote(ctx, tool, w.t, w.h, cmd, maxBytes)
}

func (in *Instance) FollowTools() []string {
	if in.script == nil || !in.offered().Allows(access.Read) {
		return nil
	}
	var out []string
	for _, st := range in.script.tools {
		if st.follow != nil {
			out = append(out, in.Name+"_"+st.name)
		}
	}
	return out
}

func (in *Instance) followTool(tool string) (*scriptTool, error) {
	short := strings.TrimPrefix(tool, in.Name+"_")
	if in.script != nil {
		for _, st := range in.script.tools {
			if st.name == short && st.follow != nil {
				return st, nil
			}
		}
	}
	return nil, i18n.E("tpl.follow.unknown", tool, strings.Join(in.FollowTools(), ", "))
}

func (in *Instance) Follow(ctx context.Context, tool string, args, cursor json.RawMessage) ([]string, json.RawMessage, error) {
	st, err := in.followTool(tool)
	if err != nil {
		return nil, nil, err
	}
	if !in.offered().Allows(st.level) {
		return nil, nil, i18n.E("tpl.access.required", tool, st.level)
	}
	if err := in.ensure(); err != nil {
		return nil, nil, err
	}
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	a, err := jsonToStarlark(args)
	if err != nil {
		return nil, nil, fmt.Errorf("arguments JSON invalides: %w", err)
	}
	if _, ok := a.(*starlark.Dict); !ok {
		return nil, nil, fmt.Errorf("arguments: objet JSON attendu")
	}
	var c starlark.Value = starlark.None
	if len(cursor) > 0 && string(cursor) != "null" {
		if c, err = jsonToStarlark(cursor); err != nil {
			return nil, nil, err
		}
	}
	v, err := in.call(ctx, st.name, st.follow, a, c)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, scriptErr(err)
	}
	return followResult(st.name, v)
}

func followResult(name string, v starlark.Value) ([]string, json.RawMessage, error) {
	d, ok := v.(*starlark.Dict)
	if !ok {
		return nil, nil, i18n.E("tpl.follow.result", name)
	}
	var lines []string
	if lv, found, _ := d.Get(starlark.String("lines")); found && lv != starlark.None {
		l, ok := lv.(*starlark.List)
		if !ok {
			return nil, nil, i18n.E("tpl.follow.result", name)
		}
		for i := range l.Len() {
			s, ok := starlark.AsString(l.Index(i))
			if !ok {
				return nil, nil, i18n.E("tpl.follow.result", name)
			}
			lines = append(lines, s)
		}
	}
	cv, _, _ := d.Get(starlark.String("cursor"))
	if cv == nil {
		cv = starlark.None
	}
	raw, err := starlarkJSON(cv)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: cursor: %w", name, err)
	}
	return lines, raw, nil
}
