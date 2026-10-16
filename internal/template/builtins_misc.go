package template

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/itchyny/gojq"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/driver/ssh"
	"github.com/agardenat/clotr/internal/i18n"
)

func runJQ(expr string, doc any) ([]any, error) {
	q, err := gojq.Parse(expr)
	if err != nil {
		return nil, fmt.Errorf("jq %q: %w", expr, err)
	}
	code, err := gojq.Compile(q)
	if err != nil {
		return nil, fmt.Errorf("jq %q: %w", expr, err)
	}
	var out []any
	iter := code.Run(doc)
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if e, isErr := v.(error); isErr {
			return nil, fmt.Errorf("jq %q: %w", expr, e)
		}
		out = append(out, v)
	}
	return out, nil
}

func builtinJQ(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var expr string
	var data starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "expr", &expr, "data", &data); err != nil {
		return nil, err
	}
	var doc any
	if s, ok := data.(starlark.String); ok {
		if err := json.Unmarshal([]byte(s), &doc); err != nil {
			return nil, i18n.E("tpl.jq_json", err)
		}
	} else {
		raw, err := starlarkJSON(data)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
	}
	out, err := runJQ(expr, doc)
	if err != nil {
		return nil, err
	}
	return toStarlark(normalizeJQ(out))
}

func normalizeJQ(v any) any {
	switch x := v.(type) {
	case []any:
		for i := range x {
			x[i] = normalizeJQ(x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = normalizeJQ(x[k])
		}
	case int:
		return int64(x)
	case *big.Int:
		return x
	}
	return v
}

var cryptoModule = &starlarkstruct.Module{
	Name: "crypto",
	Members: starlark.StringDict{
		"sign":     starlark.NewBuiltin("crypto.sign", builtinSign),
		"key_type": starlark.NewBuiltin("crypto.key_type", builtinKeyType),
	},
}

func builtinSign(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key string
	var msg starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key, "msg", &msg); err != nil {
		return nil, err
	}
	data, ok := asText(msg)
	if !ok {
		return nil, i18n.E("tpl.sign.msg")
	}
	method, sig, err := sign(key, []byte(data))
	if err != nil {
		return nil, err
	}
	return makeStruct(map[string]any{"method": method, "signature": sig})
}

func builtinKeyType(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "key", &key); err != nil {
		return nil, err
	}
	method, _, err := sign(key, nil)
	if err != nil {
		return nil, err
	}
	return starlark.String(strings.TrimSuffix(method, "-sha256")), nil
}

func sign(key string, msg []byte) (string, []byte, error) {
	key = strings.TrimSpace(key)
	if seed, err := base64.StdEncoding.DecodeString(key); err == nil && len(seed) == ed25519.SeedSize {
		return "ed25519", ed25519.Sign(ed25519.NewKeyFromSeed(seed), msg), nil
	}
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return "", nil, i18n.E("tpl.sign.key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", nil, fmt.Errorf("crypto.sign: %w", err)
	}
	switch k := parsed.(type) {
	case ed25519.PrivateKey:
		return "ed25519", ed25519.Sign(k, msg), nil
	case *rsa.PrivateKey:
		h := sha256.Sum256(msg)
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
		return "rsa-sha256", sig, err
	}
	return "", nil, i18n.E("tpl.sign.key_type", parsed)
}

var base64Module = &starlarkstruct.Module{
	Name: "base64",
	Members: starlark.StringDict{
		"encode": starlark.NewBuiltin("base64.encode", builtinB64Encode),
		"decode": starlark.NewBuiltin("base64.decode", builtinB64Decode),
	},
}

func b64Encoding(urlSafe bool) *base64.Encoding {
	if urlSafe {
		return base64.URLEncoding
	}
	return base64.StdEncoding
}

func builtinB64Encode(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data starlark.Value
	var urlSafe bool
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "data", &data, "url?", &urlSafe); err != nil {
		return nil, err
	}
	s, ok := asText(data)
	if !ok {
		return nil, i18n.E("tpl.base64")
	}
	return starlark.String(b64Encoding(urlSafe).EncodeToString([]byte(s))), nil
}

func asText(v starlark.Value) (string, bool) {
	switch x := v.(type) {
	case starlark.String:
		return string(x), true
	case starlark.Bytes:
		return string(x), true
	}
	return "", false
}

func builtinB64Decode(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data string
	var urlSafe bool
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "data", &data, "url?", &urlSafe); err != nil {
		return nil, err
	}
	out, err := b64Encoding(urlSafe).DecodeString(strings.TrimSpace(data))
	if err != nil {
		return nil, fmt.Errorf("base64.decode: %w", err)
	}
	return starlark.Bytes(out), nil
}

func (in *Instance) fileAllowed(p string) (string, error) {
	want := config.ExpandHome(p)
	for _, f := range in.files {
		if config.ExpandHome(f) == want {
			return want, nil
		}
	}
	return "", i18n.E("tpl.file_undeclared", p)
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
				if err != nil {
					return nil, err
				}
				_, err = in.readFile(full)
				return starlark.Bool(err == nil), nil
			}),
		},
	}
}

func (in *Instance) builtinEnv(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	if !slices.Contains(in.T.Env, name) {
		return nil, i18n.E("tpl.env_undeclared", name)
	}
	return starlark.String(in.getenv(name)), nil
}

func builtinParallel(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var fn starlark.Callable
	var items starlark.Iterable
	limit := 4
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "fn", &fn, "items", &items, "limit?", &limit); err != nil {
		return nil, err
	}
	var vals []starlark.Value
	it := items.Iterate()
	var x starlark.Value
	for it.Next(&x) {
		vals = append(vals, x)
	}
	it.Done()
	in, _ := thread.Local(localInstance).(*Instance)
	ctx := threadCtx(thread)
	results := make([]starlark.Value, len(vals))
	sem := make(chan struct{}, max(1, min(limit, 16)))
	var wg sync.WaitGroup
	for i, v := range vals {
		v.Freeze()
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			var out starlark.Value
			var err error
			if in != nil {
				out, err = in.call(ctx, threadTool(thread), fn, v)
			} else {
				err = i18n.E("tpl.parallel")
			}
			fields := map[string]any{"value": out, "error": ""}
			if err != nil {
				fields["value"], fields["error"] = starlark.None, scriptErr(err).Error()
			}
			if out == nil {
				fields["value"] = starlark.None
			}
			results[i], _ = makeStruct(fields)
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return starlark.NewList(results), nil
}

func builtinSprintf(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if len(args) == 0 || len(kwargs) > 0 {
		return nil, fmt.Errorf("sprintf(format, *args)")
	}
	format, ok := starlark.AsString(args[0])
	if !ok {
		return nil, i18n.E("tpl.sprintf")
	}
	var goArgs []any
	for _, a := range args[1:] {
		switch x := a.(type) {
		case starlark.Int:
			if i, ok := x.Int64(); ok {
				goArgs = append(goArgs, i)
			} else {
				goArgs = append(goArgs, x.BigInt())
			}
		case starlark.Float:
			goArgs = append(goArgs, float64(x))
		case starlark.String:
			goArgs = append(goArgs, string(x))
		case starlark.Bool:
			goArgs = append(goArgs, bool(x))
		default:
			goArgs = append(goArgs, a.String())
		}
	}
	return starlark.String(fmt.Sprintf(format, goArgs...)), nil
}

func builtinLogStats(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	var size, mtime int64
	var truncated bool
	topN := 15
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &text, "size?", &size, "mtime?", &mtime, "truncated?", &truncated, "top?", &topN); err != nil {
		return nil, err
	}
	if size == 0 {
		size = int64(len(text))
	}
	return starlark.String(LogStats(text, size, time.Unix(mtime, 0), len(text), truncated, clamp(topN, 15, 5, 40))), nil
}

func builtinRedact(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &text); err != nil {
		return nil, err
	}
	return starlark.String(ssh.Redact(text)), nil
}

var reCache sync.Map

func compileRe(p string) (*regexp.Regexp, error) {
	if v, ok := reCache.Load(p); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(p)
	if err != nil {
		return nil, fmt.Errorf("re: %w", err)
	}
	reCache.Store(p, re)
	return re, nil
}

func reBuiltin(name string, fn func(re *regexp.Regexp, s string, extra string) (starlark.Value, error), withExtra bool) *starlark.Builtin {
	return starlark.NewBuiltin("re."+name, func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var p, s, extra string
		var err error
		if withExtra {
			err = starlark.UnpackArgs(b.Name(), args, kwargs, "pattern", &p, "repl", &extra, "text", &s)
		} else {
			err = starlark.UnpackArgs(b.Name(), args, kwargs, "pattern", &p, "text", &s)
		}
		if err != nil {
			return nil, err
		}
		re, err := compileRe(p)
		if err != nil {
			return nil, err
		}
		return fn(re, s, extra)
	})
}

func strList(ss []string) starlark.Value {
	out := make([]starlark.Value, len(ss))
	for i, s := range ss {
		out[i] = starlark.String(s)
	}
	return starlark.NewList(out)
}

var reModule = &starlarkstruct.Module{
	Name: "re",
	Members: starlark.StringDict{
		"match": reBuiltin("match", func(re *regexp.Regexp, s, _ string) (starlark.Value, error) {
			return starlark.Bool(re.MatchString(s)), nil
		}, false),
		"find": reBuiltin("find", func(re *regexp.Regexp, s, _ string) (starlark.Value, error) {
			m := re.FindStringSubmatch(s)
			if m == nil {
				return starlark.None, nil
			}
			return strList(m), nil
		}, false),
		"findall": reBuiltin("findall", func(re *regexp.Regexp, s, _ string) (starlark.Value, error) {
			return strList(re.FindAllString(s, -1)), nil
		}, false),
		"split": reBuiltin("split", func(re *regexp.Regexp, s, _ string) (starlark.Value, error) {
			return strList(re.Split(s, -1)), nil
		}, false),
		"sub": reBuiltin("sub", func(re *regexp.Regexp, s, repl string) (starlark.Value, error) {
			return starlark.String(re.ReplaceAllString(s, repl)), nil
		}, true),
	},
}

func strFn(name string, fn func(string) (starlark.Value, error)) *starlark.Builtin {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var s string
		if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &s); err != nil {
			return nil, err
		}
		return fn(s)
	})
}

var urlModule = &starlarkstruct.Module{
	Name: "url",
	Members: starlark.StringDict{
		"path_escape":  strFn("url.path_escape", func(s string) (starlark.Value, error) { return starlark.String(url.PathEscape(s)), nil }),
		"query_escape": strFn("url.query_escape", func(s string) (starlark.Value, error) { return starlark.String(url.QueryEscape(s)), nil }),
		"parse_query": strFn("url.parse_query", func(s string) (starlark.Value, error) {
			q, err := url.ParseQuery(s)
			if err != nil {
				return nil, i18n.E("tpl.query", err)
			}
			d := map[string]string{}
			for k := range q {
				d[k] = q.Get(k)
			}
			return toStarlark(d)
		}),
		"parse": strFn("url.parse", func(s string) (starlark.Value, error) {
			u, err := url.Parse(s)
			if err != nil {
				return nil, i18n.E("tpl.url", err)
			}
			return makeStruct(map[string]any{"scheme": u.Scheme, "host": u.Host, "hostname": u.Hostname(), "port": u.Port(), "path": u.Path, "query": u.RawQuery})
		}),
	},
}

func builtinCompactJSON(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var s string
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &s); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(s)); err != nil {
		return nil, fmt.Errorf("compact_json: %w", err)
	}
	return starlark.String(buf.String()), nil
}
