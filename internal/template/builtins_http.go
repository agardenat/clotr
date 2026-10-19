package template

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/httpx"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/netx"
)

const (
	defaultMaxBytes = 32 << 20
	hardMaxBytes    = 512 << 20
)

var sensitivePath = regexp.MustCompile(`(?i)keytab|secret|password|token`)

type httpAuth struct {
	userEnv, passEnv, passVault, label, header, scheme string
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
	deny     []*regexp.Regexp
	ownDeny  bool
	opts     options
	client   *http.Client
}

var httpOptionKeys = []string{"base_url", "methods", "allow", "headers", "max_bytes", "timeout", "auth", "deny", "proxy", "proxy_port", "verify_tls", "ca_file"}

func checkHTTPOptions(o options) error {
	for k := range o {
		if !slices.Contains(httpOptionKeys, k) {
			return i18n.E("tpl.http.option", k, strings.Join(httpOptionKeys, ", "))
		}
	}
	methods := o.list("methods")
	for _, m := range methods {
		if m != strings.ToUpper(m) || m == "" {
			return i18n.E("tpl.http.method_case", m)
		}
	}
	for _, k := range []string{"allow", "deny"} {
		for _, a := range o.list(k) {
			if _, err := regexp.Compile(a); err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
		}
	}
	for _, m := range methods {
		if m != http.MethodGet && m != http.MethodHead && len(o.list("allow")) == 0 {
			return i18n.E("tpl.http.method_allow", m)
		}
	}
	a := o.sub("auth")
	for k := range a {
		if !slices.Contains([]string{"user_env", "password_env", "password_vault", "label", "header", "scheme"}, k) {
			return i18n.E("tpl.http.auth_key", k)
		}
	}
	if _, ok := a["scheme"]; ok && a.str("header") == "" {
		return i18n.E("tpl.http.auth_scheme")
	}
	if a.str("header") != "" && a.str("user_env") != "" {
		return i18n.E("tpl.http.auth_user")
	}
	return nil
}

func checkAuthOptions(o options) error {
	for k := range o.sub("auth") {
		if !slices.Contains([]string{"user_env", "password_env", "password_vault", "label"}, k) {
			return i18n.E("tpl.http.auth", k)
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
	_, hc.ownDeny = o["deny"]
	for _, d := range o.list("deny") {
		re, err := regexp.Compile(d)
		if err != nil {
			return nil, err
		}
		hc.deny = append(hc.deny, re)
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
		hc.auth = &httpAuth{userEnv: a.str("user_env"), passEnv: a.str("password_env"), passVault: a.str("password_vault"), label: defaultStr(a.str("label"), name), header: a.str("header"), scheme: a.str("scheme")}
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

type requestInfoKey struct{}

type requestInfo struct {
	proxy string
	tls   *netx.TLS
}

func requestTLS(v starlark.Value) (*netx.TLS, error) {
	d, err := optDict("tls", v)
	if err != nil || d == nil {
		return nil, err
	}
	t := &netx.TLS{Verify: true}
	for _, it := range d.Items() {
		k, _ := starlark.AsString(it[0])
		if k == "insecure" {
			b, ok := it[1].(starlark.Bool)
			if !ok {
				return nil, i18n.E("tpl.http.tls_insecure")
			}
			t.Verify = !bool(b)
			continue
		}
		s, ok := asText(it[1])
		if !ok {
			return nil, i18n.E("tpl.http.tls_pem", k, it[1].Type())
		}
		switch k {
		case "ca":
			t.CAPEM = []byte(s)
		case "cert":
			t.CertPEM = []byte(s)
		case "key":
			t.KeyPEM = []byte(s)
		default:
			return nil, i18n.E("tpl.http.tls", k)
		}
	}
	return t, nil
}

func (in *Instance) httpClientFor(hc *httpConn, t *netx.TLS, proxy string) (*http.Client, error) {
	if t == nil && proxy == "" {
		return in.httpClient(hc)
	}
	if t == nil {
		t = &netx.TLS{Verify: true}
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.transport != nil {
		return &http.Client{Transport: in.transport, Timeout: hc.timeout}, nil
	}
	h := sha256.New()
	for _, part := range [][]byte{[]byte(hc.name), []byte(proxy), []byte(strconv.FormatBool(t.Verify)), t.CAPEM, t.CertPEM, t.KeyPEM} {
		h.Write(part)
		h.Write([]byte{0})
	}
	key := hex.EncodeToString(h.Sum(nil))
	if c, ok := in.clients[key]; ok {
		return c, nil
	}
	port, err := hc.opts.int("proxy_port", 0)
	if err != nil {
		return nil, err
	}
	px, err := netx.ProxyURL(defaultStr(proxy, hc.opts.str("proxy")), port)
	if err != nil {
		return nil, err
	}
	verify, err := hc.opts.bool("verify_tls", true)
	if err != nil {
		return nil, err
	}
	o := *t
	o.Verify = verify && t.Verify
	o.CAFile = config.ExpandHome(hc.opts.str("ca_file"))
	tr, err := netx.TransportTLS(px, o)
	if err != nil {
		return nil, err
	}
	if in.clients == nil {
		in.clients = map[string]*http.Client{}
	}
	c := &http.Client{Transport: tr, Timeout: hc.timeout}
	in.clients[key] = c
	return c, nil
}

func checkRequestPath(hc *httpConn, method, p string) (string, error) {
	if !slices.Contains(hc.methods, method) {
		return "", i18n.E("tpl.http.method_refused", method, hc.name, strings.Join(hc.methods, ", "))
	}
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#") {
		return "", i18n.E("tpl.http.path_form", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." {
			return "", i18n.E("tpl.http.path", p)
		}
	}
	clean := path.Clean(p)
	if strings.HasSuffix(p, "/") && clean != "/" {
		clean += "/"
	}
	if !hc.ownDeny && sensitivePath.MatchString(clean) {
		return "", i18n.E("tpl.http.path_sensitive", clean)
	}
	for _, re := range hc.deny {
		if re.MatchString(clean) {
			return "", i18n.E("tpl.http.path_deny", clean, hc.name)
		}
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
			return "", i18n.E("tpl.http.path_allow", clean, hc.name)
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
	var baseV, queryV, jsonBody, bodyV, headersV, jqV, maxV, tlsV, proxyV starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "conn", &conn, "method", &method, "path", &p, "base?", &baseV, "query?", &queryV, "json?", &jsonBody, "body?", &bodyV, "headers?", &headersV, "jq?", &jqV, "max_bytes?", &maxV, "tls?", &tlsV, "proxy?", &proxyV); err != nil {
		return nil, err
	}
	reqTLS, err := requestTLS(tlsV)
	if err != nil {
		return nil, err
	}
	proxyOverride, err := optString("proxy", proxyV)
	if err != nil {
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
		return nil, i18n.E("tpl.http.at_load")
	}
	if err := denyOffline(threadCtx(thread)); err != nil {
		return nil, err
	}
	hc, ok := in.https[conn]
	if !ok {
		return nil, i18n.E("tpl.http.connector", conn, strings.Join(sortedKeys(in.https), ", "))
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
		return nil, i18n.E("tpl.http.base_url", base)
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
	if in.transport != nil {
		ctx = context.WithValue(ctx, requestInfoKey{}, requestInfo{proxy: proxyOverride, tls: reqTLS})
	}
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
			return nil, i18n.E("tpl.http.creds", conn)
		}
		switch {
		case hc.auth.header == "":
			req.SetBasicAuth(c.User, c.Pass)
		case hc.auth.scheme != "":
			req.Header.Set(hc.auth.header, hc.auth.scheme+" "+c.Pass)
		default:
			req.Header.Set(hc.auth.header, c.Pass)
		}
	}
	client, err := in.httpClientFor(hc, reqTLS, proxyOverride)
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
		return nil, i18n.E("tpl.http.too_big", method, u.Path, limit>>20)
	}
	hdr := map[string]string{}
	for k := range resp.Header {
		hdr[strings.ToLower(k)] = resp.Header.Get(k)
	}
	fields := map[string]any{"status": resp.StatusCode, "headers": hdr, "url": u.String(), "path": u.Path, "body": string(data), "data": starlark.None}
	if jqExpr != "" && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, i18n.E("tpl.http.json", method, u.Path, err)
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
		return "", i18n.E("tpl.arg.text", name, v.Type())
	}
	return s, nil
}

func optDict(name string, v starlark.Value) (*starlark.Dict, error) {
	if v == nil || v == starlark.None {
		return nil, nil
	}
	d, ok := v.(*starlark.Dict)
	if !ok {
		return nil, i18n.E("tpl.arg.dict", name, v.Type())
	}
	return d, nil
}

func optInt(name string, v starlark.Value) (int, error) {
	if v == nil || v == starlark.None {
		return 0, nil
	}
	i, ok := v.(starlark.Int)
	if !ok {
		return 0, i18n.E("tpl.arg.int", name, v.Type())
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
