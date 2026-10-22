package template

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/agardenat/clotr/internal/access"
	"github.com/agardenat/clotr/internal/driver/ssh"
	"github.com/agardenat/clotr/internal/i18n"
)

type command func(ssh.Builder) string

func (in *Instance) remote(ctx context.Context, tool string, t *Target, h *Host, build command, maxBytes int) (ssh.Result, error) {
	pool, err := in.sshPool()
	if err != nil {
		return ssh.Result{}, err
	}
	ep, login, err := in.sshEndpoint(ctx, t, h)
	if err != nil {
		return ssh.Result{}, err
	}
	if !in.sudo {
		return in.exec(ctx, pool, tool, t, ep, login, build(ssh.Builder{}), "", maxBytes)
	}
	if !in.sudoNeedsPassword(ep) {
		res, err := in.exec(ctx, pool, tool, t, ep, login, build(ssh.Builder{Sudo: true}), "", maxBytes)
		if err != nil || login == nil || !ssh.SudoNeedsPassword(res) {
			return res, err
		}
		in.setSudoNeedsPassword(ep)
	}
	pw, err := login.password(ctx)
	if err != nil {
		return ssh.Result{}, err
	}
	res, err := in.exec(ctx, pool, tool, t, ep, login, ssh.SudoWithPassword(build(ssh.Builder{})), pw+"\n", maxBytes)
	if err == nil && res.Exit != 0 && ssh.SudoPasswordRejected(res.Stderr) {
		login.forget()
		return ssh.Result{}, i18n.E("tpl.ssh.sudo_password", ep.User, ep.Host)
	}
	return res, err
}

func (in *Instance) remoteExec(ctx context.Context, tool string, t *Target, h *Host, argv []string, maxBytes int) (ssh.Result, error) {
	if !in.allowed(ctx, access.Exec) {
		return ssh.Result{}, i18n.E("tpl.access.required", "ssh exec", access.Exec)
	}
	if err := in.authorizeCommand(ctx, h.Name, argv); err != nil {
		return ssh.Result{}, err
	}
	pool, err := in.sshPool()
	if err != nil {
		return ssh.Result{}, err
	}
	ep, login, err := in.sshEndpoint(ctx, t, h)
	if err != nil {
		return ssh.Result{}, err
	}
	return in.exec(ctx, pool, tool, t, ep, login, ssh.Exec(argv), "", maxBytes)
}

func (in *Instance) exec(ctx context.Context, pool sshExecutor, tool string, t *Target, ep ssh.Endpoint, login *sshLogin, cmd, stdin string, maxBytes int) (ssh.Result, error) {
	start := time.Now()
	res, err := pool.ExecInput(ctx, ep, cmd, stdin, maxBytes)
	f := map[string]any{"tool": tool, "target": t.Name, "host": ep.Host, "user": ep.User, "command": cmd, "duration_ms": time.Since(start).Milliseconds(), "exit": res.Exit, "bytes": len(res.Stdout)}
	if err != nil {
		f["error"] = err.Error()
		if login != nil && errors.Is(err, ssh.ErrAuth) {
			login.forget()
		}
	}
	in.audit("remote_exec", f)
	return res, err
}

func format(res ssh.Result, okExits ...int) (string, error) {
	out := ssh.Redact(res.Stdout)
	if res.Truncated {
		out += "\n[sortie tronquée]"
	}
	if res.Exit != 0 && !slices.Contains(okExits, res.Exit) {
		msg := strings.TrimSpace(ssh.Redact(res.Stderr))
		if strings.Contains(msg, "a password is required") || strings.Contains(msg, "sudo:") {
			msg += " (sudo -n refusé : droits sudo sans mot de passe requis)"
		}
		if out != "" {
			return fmt.Sprintf("%s\n[exit %d] %s", out, res.Exit, msg), nil
		}
		return "", fmt.Errorf("exit %d: %s", res.Exit, msg)
	}
	return out, nil
}

func (in *Instance) sshModule() *starlarkstruct.Module {
	fns := map[string]func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error){
		"list":      in.sshList,
		"read":      in.sshRead,
		"tail":      in.sshTail,
		"grep":      in.sshGrep,
		"disk":      in.sshDisk,
		"stat_tail": in.sshStatTail,
		"recent":    in.sshRecent,
		"format":    sshFormat,
		"allowed":   in.sshAllowed,
		"exec":      in.sshExec,
	}
	m := starlark.StringDict{}
	for n, f := range fns {
		m[n] = starlark.NewBuiltin("ssh."+n, f)
	}
	return &starlarkstruct.Module{Name: "ssh", Members: m}
}

func (in *Instance) sshRun(thread *starlark.Thread, target, host string, cmd command, maxBytes int) (starlark.Value, error) {
	t, h, err := in.sshPrepare(thread, target, host)
	if err != nil {
		return nil, err
	}
	res, err := in.remote(threadCtx(thread), threadTool(thread), t, h, cmd, maxBytes)
	if err != nil {
		return nil, err
	}
	return resultValue(res, h.Name)
}

func (in *Instance) sshPrepare(thread *starlark.Thread, target, host string) (*Target, *Host, error) {
	if thread.Local(localLoading) != nil {
		return nil, nil, i18n.E("tpl.ssh.at_load")
	}
	if err := denyOffline(threadCtx(thread)); err != nil {
		return nil, nil, err
	}
	if in.sshName == "" {
		return nil, nil, i18n.E("tpl.ssh.no_connector", in.T.Name)
	}
	return in.findHost(target, host)
}

func resultValue(res ssh.Result, host string) (starlark.Value, error) {
	return makeStruct(map[string]any{"stdout": res.Stdout, "stderr": res.Stderr, "exit": res.Exit, "truncated": res.Truncated, "host": host})
}

func (in *Instance) checkPath(p string) (string, error) {
	if in.rules == nil {
		return "", i18n.E("tpl.ssh.no_connector", in.T.Name)
	}
	return in.rules.Check(p)
}

func (in *Instance) sshList(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var host, p, target, sortBy string
	depth, limit := 1, 500
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "host", &host, "path", &p, "target?", &target, "depth?", &depth, "limit?", &limit, "sort?", &sortBy); err != nil {
		return nil, err
	}
	cp, err := in.checkPath(p)
	if err != nil {
		return nil, err
	}
	return in.sshRun(thread, target, host, func(b ssh.Builder) string {
		return b.List(cp, clamp(depth, 1, 1, 4), clamp(limit, 500, 1, 5000), sortBy)
	}, maxRead)
}

func (in *Instance) sshRead(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var host, p, target string
	from, to := 0, 0
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "host", &host, "path", &p, "target?", &target, "from_line?", &from, "to_line?", &to); err != nil {
		return nil, err
	}
	cp, err := in.checkPath(p)
	if err != nil {
		return nil, err
	}
	return in.sshRun(thread, target, host, func(b ssh.Builder) string { return b.Read(cp, max(from, 0), max(to, 0), maxRead) }, maxRead+1024)
}

func (in *Instance) sshTail(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var host, p, target, filter string
	lines := 200
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "host", &host, "path", &p, "target?", &target, "lines?", &lines, "filter?", &filter); err != nil {
		return nil, err
	}
	if strings.ContainsAny(filter, "\n\r\x00") {
		return nil, i18n.E("tpl.ssh.filter")
	}
	cp, err := in.checkPath(p)
	if err != nil {
		return nil, err
	}
	cmd := func(b ssh.Builder) string { return b.Tail(cp, clamp(lines, 200, 1, maxLines)) }
	if filter != "" {
		cmd = func(b ssh.Builder) string { return b.TailFiltered(cp, filter, clamp(lines, 200, 1, maxLines)) }
	}
	return in.sshRun(thread, target, host, cmd, maxRead*4)
}

func (in *Instance) sshGrep(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var host, p, pattern, target string
	var ignoreCase, recursive, count bool
	maxMatches := 50
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "host", &host, "path", &p, "pattern", &pattern, "target?", &target, "ignore_case?", &ignoreCase, "recursive?", &recursive, "max_matches?", &maxMatches, "count?", &count); err != nil {
		return nil, err
	}
	if strings.TrimSpace(pattern) == "" || strings.ContainsAny(pattern, "\n\r\x00") {
		return nil, i18n.E("tpl.ssh.pattern")
	}
	cp, err := in.checkPath(p)
	if err != nil {
		return nil, err
	}
	if count {
		return in.sshRun(thread, target, host, func(b ssh.Builder) string {
			return b.GrepCount(cp, pattern, ignoreCase, recursive, in.rules.ExcludeGlobs(), maxRead)
		}, maxRead+1024)
	}
	return in.sshRun(thread, target, host, func(b ssh.Builder) string {
		return b.Grep(cp, pattern, ignoreCase, recursive, clamp(maxMatches, 50, 1, 500), in.rules.ExcludeGlobs(), maxRead)
	}, maxRead+1024)
}

func (in *Instance) sshDisk(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var host, p, target string
	depth := 2
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "host", &host, "path", &p, "target?", &target, "depth?", &depth); err != nil {
		return nil, err
	}
	cp, err := in.checkPath(p)
	if err != nil {
		return nil, err
	}
	return in.sshRun(thread, target, host, func(b ssh.Builder) string { return b.Disk(cp, clamp(depth, 2, 1, 4), 40) }, maxRead)
}

func (in *Instance) sshStatTail(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var host, p, target string
	sample := statsDefault
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "host", &host, "path", &p, "target?", &target, "max_bytes?", &sample); err != nil {
		return nil, err
	}
	cp, err := in.checkPath(p)
	if err != nil {
		return nil, err
	}
	sample = clamp(sample, statsDefault, 1<<20, statsMax)
	t, h, err := in.sshPrepare(thread, target, host)
	if err != nil {
		return nil, err
	}
	res, err := in.remote(threadCtx(thread), threadTool(thread), t, h, func(b ssh.Builder) string { return b.StatTail(cp, sample) }, sample+4096)
	if err != nil {
		return nil, err
	}
	fields := map[string]any{"exit": res.Exit, "stderr": res.Stderr, "stdout": res.Stdout, "truncated": res.Truncated, "host": h.Name, "size": 0, "mtime": 0, "body": ""}
	if res.Exit == 0 {
		head, body, _ := strings.Cut(res.Stdout, "\n")
		f := strings.Fields(head)
		if len(f) != 2 {
			return nil, i18n.E("tpl.stat", head)
		}
		size, _ := strconv.ParseInt(f[0], 10, 64)
		mt, _ := strconv.ParseInt(f[1], 10, 64)
		fields["size"], fields["mtime"], fields["body"] = size, mt, body
	}
	return makeStruct(fields)
}

func (in *Instance) sshRecent(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var host, target string
	var dirs *starlark.List
	minutes, limit := 1440, 2
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "host", &host, "dirs", &dirs, "target?", &target, "minutes?", &minutes, "limit?", &limit); err != nil {
		return nil, err
	}
	var ds []string
	for i := 0; i < dirs.Len(); i++ {
		d, _ := starlark.AsString(dirs.Index(i))
		cp, err := in.checkPath(d)
		if err != nil {
			return nil, err
		}
		ds = append(ds, cp)
	}
	if len(ds) == 0 {
		return nil, i18n.E("tpl.ssh.dirs")
	}
	t, h, err := in.sshPrepare(thread, target, host)
	if err != nil {
		return nil, err
	}
	res, err := in.remote(threadCtx(thread), threadTool(thread), t, h, func(b ssh.Builder) string { return b.Recent(ds, max(minutes, 1), clamp(limit, 2, 1, 20)) }, maxRead)
	if err != nil {
		return nil, err
	}
	var files []any
	for _, l := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
		f := strings.SplitN(l, " ", 3)
		if len(f) != 3 {
			continue
		}
		cp, err := in.checkPath(f[2])
		if err != nil {
			continue
		}
		mt, _ := strconv.ParseFloat(f[0], 64)
		size, _ := strconv.ParseInt(f[1], 10, 64)
		files = append(files, map[string]any{"mtime": int64(mt), "size": size, "path": cp})
	}
	return makeStruct(map[string]any{"files": files, "exit": res.Exit, "stderr": res.Stderr, "host": h.Name})
}

func sshFormat(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var res *starlarkstruct.Struct
	var ok *starlark.List
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "result", &res, "ok_exits?", &ok); err != nil {
		return nil, err
	}
	var r ssh.Result
	get := func(n string) starlark.Value {
		v, _ := res.Attr(n)
		return v
	}
	r.Stdout, _ = starlark.AsString(get("stdout"))
	r.Stderr, _ = starlark.AsString(get("stderr"))
	if e, ok := get("exit").(starlark.Int); ok {
		x, _ := e.Int64()
		r.Exit = int(x)
	}
	r.Truncated = bool(get("truncated").Truth())
	var exits []int
	for i := 0; ok != nil && i < ok.Len(); i++ {
		if e, isInt := ok.Index(i).(starlark.Int); isInt {
			x, _ := e.Int64()
			exits = append(exits, int(x))
		}
	}
	s, err := format(r, exits...)
	if err != nil {
		return nil, err
	}
	return starlark.String(s), nil
}

func (in *Instance) sshAllowed(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var p string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "path", &p); err != nil {
		return nil, err
	}
	_, err := in.checkPath(p)
	return starlark.Bool(err == nil), nil
}

func (in *Instance) sshExec(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var host, target string
	var argvL *starlark.List
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "host", &host, "argv", &argvL, "target?", &target); err != nil {
		return nil, err
	}
	var argv []string
	for i := 0; i < argvL.Len(); i++ {
		s, ok := starlark.AsString(argvL.Index(i))
		if !ok {
			return nil, i18n.E("tpl.arg.text", "argv", argvL.Index(i).Type())
		}
		argv = append(argv, s)
	}
	t, h, err := in.sshPrepare(thread, target, host)
	if err != nil {
		return nil, err
	}
	res, err := in.remoteExec(threadCtx(thread), threadTool(thread), t, h, argv, maxRead)
	if err != nil {
		return nil, err
	}
	return resultValue(res, h.Name)
}
