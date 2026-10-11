package template

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/httpx"
	"github.com/agardenat/clotr/internal/netx"
)

const (
	defaultMaxBytes = 32 << 20
	hardMaxBytes    = 512 << 20
)

var sensitivePath = regexp.MustCompile(`(?i)keytab|secret|password|token`)

type httpAuth struct {
	userEnv, passEnv, label string
}

type httpConn struct {
	name     string
	base     string
	methods  []string
	allow    []*regexp.Regexp
	headers  map[string]string
	maxBytes int
	timeout  time.Duration
	auth     *httpAuth
	opts     options
	client   *http.Client
}

var httpOptionKeys = []string{"base_url", "methods", "allow", "headers", "max_bytes", "timeout", "auth", "proxy", "proxy_port", "verify_tls", "ca_file"}

func checkHTTPOptions(o options) error {
	for k := range o {
		if !slices.Contains(httpOptionKeys, k) {
			return fmt.Errorf("option %q inconnue (%s)", k, strings.Join(httpOptionKeys, ", "))
		}
	}
	methods := o.list("methods")
	for _, m := range methods {
		if m != strings.ToUpper(m) || m == "" {
			return fmt.Errorf("methods: %q invalide (majuscules attendues)", m)
		}
	}
	for _, a := range o.list("allow") {
		if _, err := regexp.Compile(a); err != nil {
			return fmt.Errorf("allow: %w", err)
		}
	}
	for _, m := range methods {
		if m != http.MethodGet && m != http.MethodHead && len(o.list("allow")) == 0 {
			return fmt.Errorf("methods: %s exige une liste allow explicite de chemins autorisés", m)
		}
	}
	return checkAuthOptions(o)
}

func checkAuthOptions(o options) error {
	for k := range o.sub("auth") {
		if !slices.Contains([]string{"user_env", "password_env", "label"}, k) {
			return fmt.Errorf("auth.%s inconnue (user_env, password_env, label)", k)
		}
	}
	return nil
}

func newHTTPConn(name string, o options) (*httpConn, error) {
	hc := &httpConn{name: name, base: strings.TrimRight(o.str("base_url"), "/"), methods: o.list("methods"), headers: map[string]string{}, opts: o}
	if len(hc.methods) == 0 {
		hc.methods = []string{http.MethodGet}
	}
	for _, a := range o.list("allow") {
		re, err := regexp.Compile(a)
		if err != nil {
			return nil, err
		}
		hc.allow = append(hc.allow, re)
	}
	for k, v := range o.sub("headers") {
		hc.headers[k] = fmt.Sprint(v)
	}
	var err error
	if hc.maxBytes, err = o.int("max_bytes", defaultMaxBytes); err != nil {
		return nil, err
	}
	hc.timeout, err = time.ParseDuration(defaultStr(o.str("timeout"), "60s"))
	if err != nil {
		return nil, fmt.Errorf("timeout: %w", err)
	}
	if a := o.sub("auth"); len(a) > 0 {
		hc.auth = &httpAuth{userEnv: a.str("user_env"), passEnv: a.str("password_env"), label: defaultStr(a.str("label"), name)}
	}
	return hc, nil
}

func (in *Instance) httpClient(hc *httpConn) (*http.Client, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if hc.client != nil {
		return hc.client, nil
	}
	if in.transport != nil {
		hc.client = &http.Client{Transport: in.transport, Timeout: hc.timeout}
		return hc.client, nil
	}
	port, err := hc.opts.int("proxy_port", 0)
	if err != nil {
		return nil, err
	}
	px, err := netx.ProxyURL(hc.opts.str("proxy"), port)
	if err != nil {
		return nil, err
	}
	verify, err := hc.opts.bool("verify_tls", true)
	if err != nil {
		return nil, err
	}
	tr, err := netx.Transport(px, verify, config.ExpandHome(hc.opts.str("ca_file")))
	if err != nil {
		return nil, err
	}
	hc.client = &http.Client{Transport: tr, Timeout: hc.timeout}
	return hc.client, nil
}

func checkRequestPath(hc *httpConn, method, p string) (string, error) {
	if !slices.Contains(hc.methods, method) {
		return "", fmt.Errorf("méthode %s refusée par le connecteur %s (autorisées : %s)", method, hc.name, strings.Join(hc.methods, ", "))
	}
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#") {
		return "", fmt.Errorf("chemin %q invalide (absolu, sans ? ni #)", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." {
			return "", fmt.Errorf("chemin %q invalide", p)
		}
	}
	clean := path.Clean(p)
	if strings.HasSuffix(p, "/") && clean != "/" {
		clean += "/"
	}
	if sensitivePath.MatchString(clean) {
		return "", fmt.Errorf("chemin %q refusé : contient un mot-clé sensible (keytab, secret, password, token)", clean)
	}
	if len(hc.allow) > 0 {
		ok := false
		for _, re := range hc.allow {
			if re.MatchString(clean) {
				ok = true
				break
			}
		}
		if !ok {
			return "", fmt.Errorf("chemin %q hors de la liste allow du connecteur %s", clean, hc.name)
		}
	}
	return clean, nil
}

func (in *Instance) httpModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "http",
		Members: starlark.StringDict{
			"request": starlark.NewBuiltin("http.request", in.builtinHTTPRequest),
			"snippet": starlark.NewBuiltin("http.snippet", builtinSnippet),
		},
	}
}

func builtinSnippet(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	max := 300
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "text", &text, "max?", &max); err != nil {
		return nil, err
	}
	return starlark.String(httpx.Snippet([]byte(text), max)), nil
}

func (in *Instance) builtinHTTPRequest(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var conn, method, p string
	var baseV, queryV, jsonBody, bodyV, headersV, jqV, maxV starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "conn", &conn, "method", &method, "path", &p, "base?", &baseV, "query?", &queryV, "json?", &jsonBody, "body?", &bodyV, "headers?", &headersV, "jq?", &jqV, "max_bytes?", &maxV); err != nil {
		return nil, err
	}
	base, err := optString("base", baseV)
	if err != nil {
		return nil, err
	}
	body, err := optString("body", bodyV)
	if err != nil {
		return nil, err
	}
	jqExpr, err := optString("jq", jqV)
	if err != nil {
		return nil, err
	}
	query, err := optDict("query", queryV)
	if err != nil {
		return nil, err
	}
	headers, err := optDict("headers", headersV)
	if err != nil {
		return nil, err
	}
	maxBytes, err := optInt("max_bytes", maxV)
	if err != nil {
		return nil, err
	}
	if thread.Local(localLoading) != nil {
		return nil, fmt.Errorf("http.request: interdit au chargement du script")
	}
	if err := denyOffline(threadCtx(thread)); err != nil {
		return nil, err
	}
	hc, ok := in.https[conn]
	if !ok {
		return nil, fmt.Errorf("connecteur http %q inconnu (%s)", conn, strings.Join(sortedKeys(in.https), ", "))
	}
	method = strings.ToUpper(method)
	clean, err := checkRequestPath(hc, method, p)
	if err != nil {
		return nil, err
	}
	if base == "" {
		base = hc.base
	}
	bu, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || (bu.Scheme != "http" && bu.Scheme != "https") || bu.Host == "" {
		return nil, fmt.Errorf("URL de base invalide %q", base)
	}
	u := *bu
	u.Path = strings.TrimRight(bu.Path, "/") + clean
	u.RawPath = ""
	if query != nil {
		q := url.Values{}
		for _, it := range query.Items() {
			k, _ := starlark.AsString(it[0])
			switch v := it[1].(type) {
			case *starlark.List:
				for i := 0; i < v.Len(); i++ {
					q.Add(k, plain(v.Index(i)))
				}
			default:
				q.Set(k, plain(v))
			}
		}
		u.RawQuery = q.Encode()
	}
	var reader io.Reader
	contentType := ""
	if jsonBody != nil && jsonBody != starlark.None {
		raw, err := starlarkJSON(jsonBody)
		if err != nil {
			return nil, fmt.Errorf("json: %w", err)
		}
		reader, contentType = bytes.NewReader(raw), "application/json"
	} else if body != "" {
		reader = strings.NewReader(body)
	}
	limit := hc.maxBytes
	if maxBytes > 0 {
		limit = min(maxBytes, hardMaxBytes)
	}
	ctx := threadCtx(thread)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpx.UserAgent)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range hc.headers {
		req.Header.Set(k, v)
	}
	if headers != nil {
		for _, it := range headers.Items() {
			k, _ := starlark.AsString(it[0])
			req.Header.Set(k, plain(it[1]))
		}
	}
	if hc.auth != nil {
		c, ok := in.creds[conn]
		if !ok {
			return nil, fmt.Errorf("connecteur %s : identifiants non résolus", conn)
		}
		req.SetBasicAuth(c.User, c.Pass)
	}
	client, err := in.httpClient(hc)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	audit := map[string]any{"tool": threadTool(thread), "connector": conn, "method": method, "url": u.Scheme + "://" + u.Host + u.Path}
	if err != nil {
		audit["error"] = err.Error()
		in.audit("http_call", audit)
		return nil, fmt.Errorf("%s %s: %w", method, u.Path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	audit["status"], audit["bytes"], audit["duration_ms"] = resp.StatusCode, len(data), time.Since(start).Milliseconds()
	if err != nil {
		audit["error"] = err.Error()
		in.audit("http_call", audit)
		return nil, fmt.Errorf("%s %s: %w", method, u.Path, err)
	}
	in.audit("http_call", audit)
	if len(data) > limit {
		return nil, fmt.Errorf("%s %s: réponse de plus de %d Mo, affiner la requête", method, u.Path, limit>>20)
	}
	hdr := map[string]string{}
	for k := range resp.Header {
		hdr[strings.ToLower(k)] = resp.Header.Get(k)
	}
	fields := map[string]any{"status": resp.StatusCode, "headers": hdr, "url": u.String(), "path": u.Path, "body": string(data), "data": starlark.None}
	if jqExpr != "" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("%s %s: JSON illisible ou incomplet: %w", method, u.Path, err)
		}
		out, err := runJQ(jqExpr, doc)
		if err != nil {
			return nil, err
		}
		fields["data"], fields["body"] = out, ""
	}
	return makeStruct(fields)
}

func optString(name string, v starlark.Value) (string, error) {
	if v == nil || v == starlark.None {
		return "", nil
	}
	s, ok := starlark.AsString(v)
	if !ok {
		return "", fmt.Errorf("%s: texte attendu, %s reçu", name, v.Type())
	}
	return s, nil
}

func optDict(name string, v starlark.Value) (*starlark.Dict, error) {
	if v == nil || v == starlark.None {
		return nil, nil
	}
	d, ok := v.(*starlark.Dict)
	if !ok {
		return nil, fmt.Errorf("%s: dict attendu, %s reçu", name, v.Type())
	}
	return d, nil
}

func optInt(name string, v starlark.Value) (int, error) {
	if v == nil || v == starlark.None {
		return 0, nil
	}
	i, ok := v.(starlark.Int)
	if !ok {
		return 0, fmt.Errorf("%s: entier attendu, %s reçu", name, v.Type())
	}
	n, _ := i.Int64()
	return int(n), nil
}

func plain(v starlark.Value) string {
	if s, ok := starlark.AsString(v); ok {
		return s
	}
	return v.String()
}
