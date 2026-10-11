package template

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	starjson "go.starlark.net/lib/json"
	startime "go.starlark.net/lib/time"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/creds"
	"github.com/agardenat/clotr/internal/driver/ssh"
)

func TestPath(t *Template) string {
	if t.ScriptPath != "" {
		return strings.TrimSuffix(t.ScriptPath, ".star") + "_test.star"
	}
	return strings.TrimSuffix(strings.TrimSuffix(t.Source, ".yaml"), ".yml") + "_test.star"
}

func RunTests(ctx context.Context, t *Template, w io.Writer) (passed, failed int, err error) {
	path := TestPath(t)
	src, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, fmt.Errorf("tests du template %s: %w", t.Name, err)
	}
	h := &testHarness{t: t}
	thread := &starlark.Thread{Name: "load", Print: func(_ *starlark.Thread, msg string) { fmt.Fprintln(w, msg) }}
	globals, err := starlark.ExecFileOptions(fileOptions, thread, path, src, h.predeclared())
	if err != nil {
		return 0, 0, fmt.Errorf("%s", scriptTrace(err))
	}
	globals.Freeze()
	var names []string
	for n, v := range globals {
		if _, ok := v.(starlark.Callable); ok && strings.HasPrefix(n, "test_") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		start := time.Now()
		th := &starlark.Thread{Name: n, Print: func(_ *starlark.Thread, msg string) { fmt.Fprintln(w, "  "+msg) }}
		th.SetLocal(localCtx, ctx)
		th.SetMaxExecutionSteps(maxScriptSteps)
		_, err := starlark.Call(th, globals[n].(starlark.Callable), nil, nil)
		if err != nil {
			failed++
			fmt.Fprintf(w, "FAIL %s (%s)\n%s\n", n, time.Since(start).Round(time.Millisecond), indent(scriptTrace(err)))
			continue
		}
		passed++
		fmt.Fprintf(w, "ok   %s (%s)\n", n, time.Since(start).Round(time.Millisecond))
	}
	return passed, failed, nil
}

func indent(s string) string {
	return "  " + strings.ReplaceAll(strings.TrimSpace(s), "\n", "\n  ")
}

type testHarness struct {
	t *Template
}

func (h *testHarness) predeclared() starlark.StringDict {
	return starlark.StringDict{
		"template": &starlarkstruct.Module{Name: "template", Members: starlark.StringDict{
			"instance": starlark.NewBuiltin("template.instance", h.newInstance),
		}},
		"assert":  assertModule,
		"json":    starjson.Module,
		"time":    startime.Module,
		"struct":  starlark.NewBuiltin("struct", starlarkstruct.Make),
		"sprintf": starlark.NewBuiltin("sprintf", builtinSprintf),
		"jq":      starlark.NewBuiltin("jq", builtinJQ),
		"base64":  base64Module,
		"crypto":  cryptoModule,
		"catch":   starlark.NewBuiltin("catch", builtinCatch),
	}
}

func (h *testHarness) newInstance(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	name := "test"
	var params, env, files, credsD *starlark.Dict
	var httpMock, sshMock starlark.Value
	var now string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name?", &name, "params?", &params, "http?", &httpMock, "ssh?", &sshMock, "env?", &env, "files?", &files, "now?", &now, "creds?", &credsD); err != nil {
		return nil, err
	}
	given := map[string]any{}
	if params != nil {
		g, err := fromStarlark(params)
		if err != nil {
			return nil, err
		}
		given = g.(map[string]any)
	}
	in, err := NewInstance(name, h.t, given)
	if err != nil {
		return nil, err
	}
	ti := &testInstance{in: in}
	in.Print = func(msg string) { fmt.Println("  " + msg) }
	envMap := dictStrings(env)
	in.getenv = func(k string) string { return envMap[k] }
	fileMap := map[string]string{}
	for k, v := range dictStrings(files) {
		fileMap[config.ExpandHome(k)] = v
	}
	in.readFile = func(p string) ([]byte, error) {
		if v, ok := fileMap[p]; ok {
			return []byte(v), nil
		}
		return nil, os.ErrNotExist
	}
	if now != "" {
		ts, err := time.Parse(time.RFC3339, now)
		if err != nil {
			return nil, fmt.Errorf("now: %w", err)
		}
		in.now = func() time.Time { return ts }
	}
	in.transport = &mockTransport{ti: ti, mock: httpMock}
	in.pool = &mockSSH{ti: ti, mock: sshMock}
	given2 := dictTuples(credsD)
	for cn, hc := range in.https {
		if hc.auth == nil {
			continue
		}
		p := creds.Pair{User: "user", Pass: "pass"}
		if v, ok := given2[cn]; ok && len(v) == 2 {
			p = creds.Pair{User: v[0], Pass: v[1]}
		}
		in.creds[cn] = p
	}
	if in.sshName != "" && len(in.conns[in.sshName].sub("auth")) > 0 {
		p := creds.Pair{User: "user", Pass: "pass"}
		if v, ok := given2[in.sshName]; ok && len(v) == 2 {
			p = creds.Pair{User: v[0], Pass: v[1]}
		}
		in.creds[in.sshName] = p
	}
	return ti, nil
}

func dictStrings(d *starlark.Dict) map[string]string {
	out := map[string]string{}
	if d == nil {
		return out
	}
	for _, it := range d.Items() {
		k, _ := starlark.AsString(it[0])
		out[k] = plain(it[1])
	}
	return out
}

func dictTuples(d *starlark.Dict) map[string][]string {
	out := map[string][]string{}
	if d == nil {
		return out
	}
	for _, it := range d.Items() {
		k, _ := starlark.AsString(it[0])
		if t, ok := it[1].(starlark.Tuple); ok {
			for _, e := range t {
				out[k] = append(out[k], plain(e))
			}
		}
	}
	return out
}

type testInstance struct {
	in       *Instance
	mu       sync.Mutex
	requests []map[string]any
	commands []map[string]any
}

func (ti *testInstance) String() string        { return "template.instance(" + ti.in.Name + ")" }
func (ti *testInstance) Type() string          { return "template.instance" }
func (ti *testInstance) Freeze()               {}
func (ti *testInstance) Truth() starlark.Bool  { return true }
func (ti *testInstance) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable") }
func (ti *testInstance) AttrNames() []string {
	return []string{"call", "commands", "discover", "environment", "error", "fn", "requests", "tools"}
}

func (ti *testInstance) Attr(name string) (starlark.Value, error) {
	switch name {
	case "discover":
		return starlark.NewBuiltin("discover", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs(b.Name(), args, kwargs); err != nil {
				return nil, err
			}
			if err := ti.in.Discover(threadCtx(thread), "", 0, true); err != nil {
				return nil, err
			}
			return ti.in.invValue, nil
		}), nil
	case "call", "error":
		return starlark.NewBuiltin(name, func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var tool string
			var targs *starlark.Dict
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "tool", &tool, "args?", &targs); err != nil {
				return nil, err
			}
			raw := []byte("{}")
			if targs != nil {
				var err error
				if raw, err = starlarkJSON(targs); err != nil {
					return nil, err
				}
			}
			for _, tl := range ti.in.Tools() {
				if tl.Name() != ti.in.Name+"_"+tool {
					continue
				}
				out, err := tl.Call(threadCtx(thread), raw)
				if name == "error" {
					if err == nil {
						return starlark.String(""), nil
					}
					return starlark.String(err.Error()), nil
				}
				if err != nil {
					return nil, fmt.Errorf("%s: %w", tool, err)
				}
				return starlark.String(out), nil
			}
			return nil, fmt.Errorf("outil %q inconnu (%s)", tool, strings.Join(ti.in.ToolNames(), ", "))
		}), nil
	case "fn":
		return starlark.NewBuiltin(name, func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if len(args) == 0 {
				return nil, fmt.Errorf("fn(nom, *args)")
			}
			fname, _ := starlark.AsString(args[0])
			if ti.in.script == nil {
				return nil, fmt.Errorf("template sans script")
			}
			fn, ok := ti.in.script.globals[fname].(starlark.Callable)
			if !ok {
				return nil, fmt.Errorf("fonction %q absente du script", fname)
			}
			v, err := ti.in.call(threadCtx(thread), fname, fn, args[1:]...)
			if err != nil {
				return nil, scriptErr(err)
			}
			return v, nil
		}), nil
	case "environment":
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			return toStarlark(ti.in.EnvironmentLines())
		}), nil
	case "tools":
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			out := map[string]any{}
			for _, tl := range ti.in.Tools() {
				out[strings.TrimPrefix(tl.Name(), ti.in.Name+"_")] = map[string]any{"description": tl.Description(), "schema": string(tl.Schema())}
			}
			return toStarlark(out)
		}), nil
	case "requests":
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			ti.mu.Lock()
			defer ti.mu.Unlock()
			return toStarlark(append([]map[string]any(nil), ti.requests...))
		}), nil
	case "commands":
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			ti.mu.Lock()
			defer ti.mu.Unlock()
			return toStarlark(append([]map[string]any(nil), ti.commands...))
		}), nil
	}
	return nil, nil
}

type mockTransport struct {
	ti   *testInstance
	mock starlark.Value
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}
	query := map[string]any{}
	for k, v := range req.URL.Query() {
		query[k] = strings.Join(v, ",")
	}
	headers := map[string]any{}
	for k := range req.Header {
		headers[strings.ToLower(k)] = req.Header.Get(k)
	}
	rec := map[string]any{"method": req.Method, "url": req.URL.String(), "host": req.URL.Host, "path": req.URL.Path, "query": query, "headers": headers, "body": string(body)}
	m.ti.mu.Lock()
	m.ti.requests = append(m.ti.requests, rec)
	m.ti.mu.Unlock()
	status, out, hdr, err := m.respond(rec)
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	for k, v := range hdr {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(bytes.NewReader(out)), Request: req}, nil
}

func (m *mockTransport) respond(rec map[string]any) (int, []byte, map[string]string, error) {
	var resp starlark.Value
	switch mk := m.mock.(type) {
	case nil, starlark.NoneType:
		return 0, nil, nil, fmt.Errorf("aucun mock http")
	case *starlark.Dict:
		key := fmt.Sprintf("%s %s", rec["method"], rec["path"])
		v, found, _ := mk.Get(starlark.String(key))
		if !found {
			v, found, _ = mk.Get(starlark.String("*"))
		}
		if !found {
			return http.StatusNotFound, []byte("mock: aucune route pour " + key), nil, nil
		}
		resp = v
		if fn, ok := v.(starlark.Callable); ok {
			r, err := callMock(fn, rec)
			if err != nil {
				return 0, nil, nil, err
			}
			resp = r
		}
	case starlark.Callable:
		r, err := callMock(mk, rec)
		if err != nil {
			return 0, nil, nil, err
		}
		resp = r
	default:
		return 0, nil, nil, fmt.Errorf("mock http: dict ou fonction attendu")
	}
	return decodeMockResponse(resp)
}

func callMock(fn starlark.Callable, rec map[string]any) (starlark.Value, error) {
	req, err := makeStruct(rec)
	if err != nil {
		return nil, err
	}
	th := &starlark.Thread{Name: "mock"}
	th.SetMaxExecutionSteps(maxScriptSteps)
	v, err := starlark.Call(th, fn, starlark.Tuple{req}, nil)
	if err != nil {
		return nil, fmt.Errorf("mock: %s", scriptTrace(err))
	}
	return v, nil
}

func decodeMockResponse(v starlark.Value) (int, []byte, map[string]string, error) {
	g, err := fromStarlark(v)
	if err != nil {
		return 0, nil, nil, err
	}
	m, ok := g.(map[string]any)
	if !ok {
		return 0, nil, nil, fmt.Errorf("mock http: réponse dict attendue (status, body ou json, headers)")
	}
	status := 200
	if s, ok := m["status"].(int64); ok {
		status = int(s)
	}
	var out []byte
	if j, ok := m["json"]; ok {
		raw, err := starlarkJSONAny(j)
		if err != nil {
			return 0, nil, nil, err
		}
		out = raw
	} else if b, ok := m["body"].(string); ok {
		out = []byte(b)
	}
	hdr := map[string]string{}
	if h, ok := m["headers"].(map[string]any); ok {
		for k, v := range h {
			hdr[k] = fmt.Sprint(v)
		}
	}
	return status, out, hdr, nil
}

type mockSSH struct {
	ti   *testInstance
	mock starlark.Value
}

func (m *mockSSH) Close() {}

func (m *mockSSH) ExecInput(_ context.Context, e ssh.Endpoint, cmd, stdin string, maxBytes int) (ssh.Result, error) {
	m.ti.mu.Lock()
	m.ti.commands = append(m.ti.commands, map[string]any{"host": e.Host, "user": e.User, "command": cmd, "stdin": stdin != ""})
	m.ti.mu.Unlock()
	fn, ok := m.mock.(starlark.Callable)
	if !ok {
		return ssh.Result{}, fmt.Errorf("aucun mock ssh")
	}
	th := &starlark.Thread{Name: "mock-ssh"}
	th.SetMaxExecutionSteps(maxScriptSteps)
	v, err := starlark.Call(th, fn, starlark.Tuple{starlark.String(e.Host), starlark.String(cmd)}, nil)
	if err != nil {
		return ssh.Result{}, fmt.Errorf("mock ssh: %s", scriptTrace(err))
	}
	if s, ok := v.(starlark.String); ok {
		return ssh.Result{Stdout: string(s)}, nil
	}
	g, err := fromStarlark(v)
	if err != nil {
		return ssh.Result{}, err
	}
	d, ok := g.(map[string]any)
	if !ok {
		return ssh.Result{}, fmt.Errorf("mock ssh: texte ou dict (stdout, stderr, exit) attendu")
	}
	r := ssh.Result{}
	r.Stdout, _ = d["stdout"].(string)
	r.Stderr, _ = d["stderr"].(string)
	if x, ok := d["exit"].(int64); ok {
		r.Exit = int(x)
	}
	if maxBytes > 0 && len(r.Stdout) > maxBytes {
		r.Stdout, r.Truncated = r.Stdout[:maxBytes], true
	}
	return r, nil
}

func starlarkJSONAny(v any) ([]byte, error) {
	sv, err := toStarlark(v)
	if err != nil {
		return nil, err
	}
	return starlarkJSON(sv)
}

var assertModule = &starlarkstruct.Module{
	Name: "assert",
	Members: starlark.StringDict{
		"eq": starlark.NewBuiltin("assert.eq", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var x, y, msg starlark.Value
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "got", &x, "want", &y, "msg?", &msg); err != nil {
				return nil, err
			}
			eq, err := starlark.Equal(x, y)
			if err != nil {
				return nil, err
			}
			if !eq {
				return nil, fmt.Errorf("%sobtenu %s, attendu %s", prefix(msg), x.String(), y.String())
			}
			return starlark.None, nil
		}),
		"true": starlark.NewBuiltin("assert.true", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var x, msg starlark.Value
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "cond", &x, "msg?", &msg); err != nil {
				return nil, err
			}
			if !x.Truth() {
				return nil, fmt.Errorf("%scondition fausse", prefix(msg))
			}
			return starlark.None, nil
		}),
		"contains": starlark.NewBuiltin("assert.contains", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var hay, needle string
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &hay, "sub", &needle); err != nil {
				return nil, err
			}
			if !strings.Contains(hay, needle) {
				return nil, fmt.Errorf("%q absent de :\n%s", needle, hay)
			}
			return starlark.None, nil
		}),
		"not_contains": starlark.NewBuiltin("assert.not_contains", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var hay, needle string
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &hay, "sub", &needle); err != nil {
				return nil, err
			}
			if strings.Contains(hay, needle) {
				return nil, fmt.Errorf("%q présent dans :\n%s", needle, hay)
			}
			return starlark.None, nil
		}),
		"fails": starlark.NewBuiltin("assert.fails", func(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var fn starlark.Callable
			var sub string
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "fn", &fn, "sub", &sub); err != nil {
				return nil, err
			}
			_, err := starlark.Call(thread, fn, nil, nil)
			if err == nil {
				return nil, fmt.Errorf("aucune erreur, %q attendu", sub)
			}
			if msg := scriptErr(err).Error(); !strings.Contains(msg, sub) {
				return nil, fmt.Errorf("erreur %q sans %q", msg, sub)
			}
			return starlark.None, nil
		}),
	},
}

func prefix(msg starlark.Value) string {
	if msg == nil || msg == starlark.None {
		return ""
	}
	return plain(msg) + " : "
}
