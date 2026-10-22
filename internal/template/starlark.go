package template

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	gotime "time"

	starjson "go.starlark.net/lib/json"
	starmath "go.starlark.net/lib/math"
	startime "go.starlark.net/lib/time"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"

	"github.com/agardenat/clotr/internal/access"
	"github.com/agardenat/clotr/internal/i18n"
)

var maxScriptSteps uint64 = 500_000_000

var moduleRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*\.star$`)

var fileOptions = &syntax.FileOptions{Set: true, While: true, TopLevelControl: true, GlobalReassign: true, Recursion: true}

type script struct {
	globals  starlark.StringDict
	discover starlark.Callable
	tools    []*scriptTool
}

type scriptTool struct {
	name   string
	desc   starlark.Value
	schema json.RawMessage
	fn     starlark.Callable
	level  access.Level
}

type memoEntry struct {
	once sync.Once
	v    starlark.Value
	err  error
}

const (
	localCtx      = "clotr.ctx"
	localInstance = "clotr.instance"
	localTool     = "clotr.tool"
	localLoading  = "clotr.loading"
)

var scriptPredeclared = []string{"http", "ssh", "jq", "json", "time", "math", "crypto", "base64", "file", "env", "parallel", "catch", "sprintf", "logstats", "redact", "instance", "tool", "struct", "re", "url", "compact_json", "yaml", "sleep"}

func checkScript(t *Template) error {
	_, _, err := starlark.SourceProgramOptions(fileOptions, t.ScriptPath, t.ScriptSrc, func(name string) bool {
		for _, p := range scriptPredeclared {
			if p == name {
				return true
			}
		}
		return false
	})
	return err
}

func (in *Instance) predeclared() starlark.StringDict {
	return starlark.StringDict{
		"http":         in.httpModule(),
		"ssh":          in.sshModule(),
		"jq":           starlark.NewBuiltin("jq", builtinJQ),
		"json":         starjson.Module,
		"time":         startime.Module,
		"math":         starmath.Module,
		"crypto":       cryptoModule,
		"base64":       base64Module,
		"file":         in.fileModule(),
		"env":          starlark.NewBuiltin("env", in.builtinEnv),
		"parallel":     starlark.NewBuiltin("parallel", builtinParallel),
		"catch":        starlark.NewBuiltin("catch", builtinCatch),
		"sprintf":      starlark.NewBuiltin("sprintf", builtinSprintf),
		"logstats":     starlark.NewBuiltin("logstats", builtinLogStats),
		"redact":       starlark.NewBuiltin("redact", builtinRedact),
		"instance":     in.instanceModule(),
		"tool":         starlark.NewBuiltin("tool", in.builtinTool),
		"struct":       starlark.NewBuiltin("struct", starlarkstruct.Make),
		"re":           reModule,
		"url":          urlModule,
		"compact_json": starlark.NewBuiltin("compact_json", builtinCompactJSON),
		"yaml":         yamlModule,
		"sleep":        starlark.NewBuiltin("sleep", in.builtinSleep),
	}
}

const maxSleep = 60 * gotime.Second

func (in *Instance) builtinSleep(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var secs starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "seconds", &secs); err != nil {
		return nil, err
	}
	f, ok := starlark.AsFloat(secs)
	if !ok || f < 0 {
		return nil, i18n.E("tpl.star.sleep", secs.String())
	}
	if thread.Local(localLoading) != nil {
		return nil, i18n.E("tpl.star.sleep_load")
	}
	d := min(gotime.Duration(f*float64(gotime.Second)), maxSleep)
	return starlark.None, in.sleep(threadCtx(thread), d)
}

func sleepCtx(ctx context.Context, d gotime.Duration) error {
	t := gotime.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (in *Instance) readModule(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (in *Instance) loadScript() error {
	in.script = &script{}
	in.loaded = map[string]*loadEntry{}
	thread := in.newThread(context.Background(), "load")
	thread.SetLocal(localLoading, true)
	globals, err := starlark.ExecFileOptions(fileOptions, thread, in.T.ScriptPath, in.T.ScriptSrc, in.predeclared())
	if err != nil {
		return fmt.Errorf("script %s: %s", in.T.Script, scriptTrace(err))
	}
	globals.Freeze()
	in.script.globals = globals
	if d, ok := globals["discover"]; ok {
		fn, ok := d.(starlark.Callable)
		if !ok {
			return i18n.E("tpl.star.discover", in.T.Script)
		}
		in.script.discover = fn
	}
	return nil
}

type loadEntry struct {
	globals starlark.StringDict
	err     error
	done    bool
}

func (in *Instance) loadModule(thread *starlark.Thread, module string) (starlark.StringDict, error) {
	if thread.Local(localLoading) == nil {
		return nil, i18n.E("tpl.star.load_time")
	}
	if !moduleRe.MatchString(module) {
		return nil, i18n.E("tpl.star.load_module", module)
	}
	if e, ok := in.loaded[module]; ok {
		if !e.done {
			return nil, fmt.Errorf("load %q: cycle", module)
		}
		return e.globals, e.err
	}
	e := &loadEntry{}
	in.loaded[module] = e
	path := filepath.Join(filepath.Dir(in.T.ScriptPath), module)
	src, err := in.readModule(path)
	if err != nil {
		e.err, e.done = fmt.Errorf("load %q: %w", module, err), true
		return nil, e.err
	}
	in.loadedSrc = append(in.loadedSrc, src...)
	globals, err := starlark.ExecFileOptions(fileOptions, thread, path, src, in.predeclared())
	if err == nil {
		globals.Freeze()
	}
	e.globals, e.err, e.done = globals, err, true
	return globals, err
}

type offlineKey struct{}

type offlineRun struct {
	network atomic.Bool
}

var errOffline error = i18n.Key("tpl.star.offline")

func offline(ctx context.Context) bool {
	return ctx.Value(offlineKey{}) != nil
}

func denyOffline(ctx context.Context) error {
	r, ok := ctx.Value(offlineKey{}).(*offlineRun)
	if !ok {
		return nil
	}
	r.network.Store(true)
	return errOffline
}

func (in *Instance) newThread(ctx context.Context, name string) *starlark.Thread {
	thread := &starlark.Thread{
		Name: in.Name + "/" + name,
		Print: func(_ *starlark.Thread, msg string) {
			if in.Print != nil && !offline(ctx) {
				in.Print(msg)
			}
		},
	}
	thread.Load = in.loadModule
	thread.SetMaxExecutionSteps(maxScriptSteps)
	thread.SetLocal(localCtx, ctx)
	thread.SetLocal(localInstance, in)
	thread.SetLocal(localTool, name)
	if in.now != nil {
		now := in.now
		startime.SetNow(thread, func() (gotime.Time, error) { return now(), nil })
	}
	return thread
}

func (in *Instance) call(ctx context.Context, name string, fn starlark.Callable, args ...starlark.Value) (starlark.Value, error) {
	thread := in.newThread(ctx, name)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			thread.Cancel(ctx.Err().Error())
		case <-done:
		}
	}()
	v, err := starlark.Call(thread, fn, args, nil)
	close(done)
	return v, err
}

func threadCtx(thread *starlark.Thread) context.Context {
	if c, ok := thread.Local(localCtx).(context.Context); ok {
		return c
	}
	return context.Background()
}

func threadTool(thread *starlark.Thread) string {
	s, _ := thread.Local(localTool).(string)
	return s
}

func (in *Instance) builtinTool(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if thread.Local(localLoading) == nil {
		return nil, i18n.E("tpl.star.tool_time")
	}
	var name string
	var desc starlark.Value
	var schema *starlark.Dict
	var fn starlark.Callable
	var lvl string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name, "description", &desc, "schema", &schema, "fn", &fn, "access?", &lvl); err != nil {
		return nil, err
	}
	level, err := access.Parse(lvl)
	if err != nil {
		return nil, fmt.Errorf("tool %s: %w", name, err)
	}
	if !identRe.MatchString(name) {
		return nil, i18n.E("tpl.star.tool_name", name)
	}
	if _, ok := desc.(starlark.String); !ok {
		if _, ok := desc.(starlark.Callable); !ok {
			return nil, i18n.E("tpl.star.tool_desc", name)
		}
	}
	raw, err := starlarkJSON(schema)
	if err != nil {
		return nil, fmt.Errorf("tool %s: schema: %w", name, err)
	}
	var head struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &head) != nil || head.Type != "object" {
		return nil, i18n.E("tpl.star.tool_schema", name)
	}
	for _, st := range in.script.tools {
		if st.name == name {
			return nil, i18n.E("tpl.star.tool_dup", name)
		}
	}
	in.script.tools = append(in.script.tools, &scriptTool{name: name, desc: desc, schema: raw, fn: fn, level: level})
	return starlark.None, nil
}

func (in *Instance) checkToolNames() error {
	seen := map[string]bool{}
	for _, n := range in.allToolNames() {
		if seen[n] {
			return i18n.E("tpl.star.tool_twice", n)
		}
		seen[n] = true
	}
	if len(seen) == 0 {
		return i18n.E("tpl.star.no_tool")
	}
	for _, c := range in.T.Companions {
		if !seen[in.Name+"_"+c] {
			return i18n.E("tpl.star.companion", c)
		}
	}
	return nil
}

func (in *Instance) ToolNames() []string {
	return in.toolNames(in.offered())
}

func (in *Instance) gatedToolNames() []string {
	var out []string
	granted := in.toolNames(in.Access())
	for _, n := range in.ToolNames() {
		if !slices.Contains(granted, n) {
			out = append(out, n)
		}
	}
	return out
}

func (in *Instance) allToolNames() []string {
	return in.toolNames(access.Create)
}

func (in *Instance) toolNames(level access.Level) []string {
	var names []string
	if in.script != nil {
		for _, st := range in.script.tools {
			if level.Allows(st.level) {
				names = append(names, in.Name+"_"+st.name)
			}
		}
	}
	for _, ts := range in.tools {
		if level.Allows(kinds[ts.Kind].level) {
			names = append(names, in.Name+"_"+ts.ToolName())
		}
	}
	return names
}

func (in *Instance) runDiscover(ctx context.Context, inv *Inventory) error {
	ctxv, err := makeStruct(map[string]any{"params": in.params, "targets": inv.Targets})
	if err != nil {
		return err
	}
	v, err := in.call(ctx, "discover", in.script.discover, ctxv)
	if err != nil {
		return fmt.Errorf("%s", scriptTrace(err))
	}
	var res struct {
		Targets  []*Target `json:"targets"`
		Lines    []string  `json:"lines"`
		Warnings []string  `json:"warnings"`
		Data     any       `json:"data"`
	}
	if err := decodeStarlark(v, &res); err != nil {
		return i18n.E("tpl.star.discover_result", err)
	}
	for i, t := range res.Targets {
		if t == nil || t.Name == "" || !targetKinds.MatchString(t.Kind) {
			return i18n.E("tpl.star.discover_target", i)
		}
		if t.Attrs == nil {
			t.Attrs = map[string]string{}
		}
		for j, n := range t.Networks {
			_, ipn, err := net.ParseCIDR(strings.TrimSpace(n))
			if err != nil {
				return i18n.E("tpl.star.discover_cidr", i, j, n)
			}
			t.Networks[j] = ipn.String()
		}
	}
	inv.Targets, inv.Lines, inv.Warnings, inv.Data = res.Targets, res.Lines, res.Warnings, res.Data
	return nil
}

func (in *Instance) instanceModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "instance",
		Members: starlark.StringDict{
			"name":      starlark.String(in.Name),
			"params":    frozen(in.params),
			"inventory": starlark.NewBuiltin("instance.inventory", in.builtinInventory),
			"target":    starlark.NewBuiltin("instance.target", in.builtinTarget),
			"find_host": starlark.NewBuiltin("instance.find_host", in.builtinFindHost),
			"memo":      starlark.NewBuiltin("instance.memo", in.builtinMemo),
		},
	}
}

func frozen(v any) starlark.Value {
	sv, err := toStarlark(v)
	if err != nil {
		return starlark.None
	}
	sv.Freeze()
	return sv
}

func (in *Instance) builtinInventory(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs(b.Name(), args, kwargs); err != nil {
		return nil, err
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.invValue == nil {
		return nil, i18n.E("tpl.not_discovered", in.Name)
	}
	return in.invValue, nil
}

func (in *Instance) targetValue(name string) (starlark.Value, error) {
	in.mu.Lock()
	inv := in.invValue
	in.mu.Unlock()
	if inv == nil {
		return nil, i18n.E("tpl.not_discovered", in.Name)
	}
	targets, _, _ := inv.(*starlark.Dict).Get(starlark.String("targets"))
	list, _ := targets.(*starlark.List)
	for i := 0; list != nil && i < list.Len(); i++ {
		d := list.Index(i).(*starlark.Dict)
		n, _, _ := d.Get(starlark.String("name"))
		if s, _ := starlark.AsString(n); s == name {
			return d, nil
		}
	}
	return nil, i18n.E("tpl.star.target_missing", name)
}

func (in *Instance) builtinTarget(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	t, err := in.target(name)
	if err != nil {
		return nil, err
	}
	return in.targetValue(t.Name)
}

func (in *Instance) builtinFindHost(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var host, target string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "host", &host, "target?", &target); err != nil {
		return nil, err
	}
	t, h, err := in.findHost(target, host)
	if err != nil {
		return nil, err
	}
	tv, err := in.targetValue(t.Name)
	if err != nil {
		return nil, err
	}
	hv, err := toStarlark(h)
	if err != nil {
		return nil, err
	}
	return starlark.Tuple{tv, hv}, nil
}

func (in *Instance) builtinMemo(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key string
	var fn starlark.Callable
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key, "fn", &fn); err != nil {
		return nil, err
	}
	in.mu.Lock()
	e, ok := in.memo[key]
	if !ok {
		e = &memoEntry{}
		in.memo[key] = e
	}
	in.mu.Unlock()
	e.once.Do(func() {
		e.v, e.err = starlark.Call(thread, fn, nil, nil)
		if e.err == nil {
			e.v.Freeze()
		}
	})
	if e.err != nil {
		in.mu.Lock()
		if in.memo[key] == e {
			delete(in.memo, key)
		}
		in.mu.Unlock()
		return nil, scriptErr(e.err)
	}
	return e.v, nil
}

func builtinCatch(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if len(args) == 0 {
		return nil, i18n.E("tpl.star.catch_fn")
	}
	fn, ok := args[0].(starlark.Callable)
	if !ok {
		return nil, i18n.E("tpl.star.catch", args[0].Type())
	}
	v, err := starlark.Call(thread, fn, args[1:], kwargs)
	if err != nil {
		if strings.Contains(err.Error(), "Starlark computation cancelled") {
			return nil, err
		}
		return makeStruct(map[string]any{"value": starlark.None, "error": scriptErr(err).Error()})
	}
	return makeStruct(map[string]any{"value": v, "error": ""})
}
