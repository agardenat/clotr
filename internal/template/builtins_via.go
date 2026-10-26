package template

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/driver/ssh"
	"github.com/agardenat/clotr/internal/i18n"
)

type httpVia struct {
	host    string
	command []string
}

func (in *Instance) sendVia(ctx context.Context, c *httpCall) (*httpReply, error) {
	v := c.hc.via
	if c.method != http.MethodGet && c.method != http.MethodHead {
		return nil, i18n.E("tpl.http.via_method", c.method, c.clean)
	}
	target := c.clean
	if len(c.query) > 0 {
		target += "?" + c.query.Encode()
	}
	accept := "application/json"
	for _, h := range []map[string]string{c.hc.headers, c.headers} {
		for k, val := range h {
			if strings.EqualFold(k, "Accept") {
				accept = val
			}
		}
	}
	argv := make([]string, len(v.command))
	for i, a := range v.command {
		argv[i] = strings.NewReplacer("%u", target, "%a", accept).Replace(a)
	}
	pool, err := in.sshPool()
	if err != nil {
		return nil, err
	}
	ep, _, err := in.sshEndpoint(ctx, &Target{}, &Host{Name: v.host})
	if err != nil {
		return nil, err
	}
	start := time.Now()
	res, err := pool.ExecInput(ctx, ep, ssh.Exec(argv), "", c.limit+64<<10)
	audit := map[string]any{"tool": c.tool, "connector": c.hc.name, "method": c.method, "url": c.clean, "via": v.host}
	if err != nil {
		audit["error"] = err.Error()
		in.audit("http_call", audit)
		return nil, err
	}
	u := &url.URL{Path: c.clean, RawQuery: c.query.Encode()}
	if res.Exit != 0 {
		audit["error"] = "exit " + strconv.Itoa(res.Exit)
		in.audit("http_call", audit)
		return nil, i18n.E("tpl.http.via_exit", c.method, c.clean, v.host, res.Exit, strings.TrimSpace(ssh.Redact(res.Stderr)))
	}
	rep, ok := parseHTTPOutput([]byte(res.Stdout))
	if !ok {
		audit["error"] = "no HTTP response"
		in.audit("http_call", audit)
		return nil, i18n.E("tpl.http.via_response", c.method, c.clean, v.host, strings.TrimSpace(ssh.Redact(res.Stderr)))
	}
	rep.url = u
	audit["status"], audit["bytes"], audit["duration_ms"] = rep.status, len(rep.data), time.Since(start).Milliseconds()
	in.audit("http_call", audit)
	return rep, nil
}

func parseHTTPOutput(out []byte) (*httpReply, bool) {
	for {
		end := bytes.Index(out, []byte("\r\n\r\n"))
		sep := 4
		if lf := bytes.Index(out, []byte("\n\n")); lf >= 0 && (end < 0 || lf < end) {
			end, sep = lf, 2
		}
		if end < 0 || !bytes.HasPrefix(out, []byte("HTTP/")) {
			return nil, false
		}
		lines := strings.Split(strings.ReplaceAll(string(out[:end]), "\r\n", "\n"), "\n")
		f := strings.Fields(lines[0])
		if len(f) < 2 {
			return nil, false
		}
		status, err := strconv.Atoi(f[1])
		if err != nil {
			return nil, false
		}
		body := out[end+sep:]
		if status >= 100 && status < 200 {
			out = body
			continue
		}
		hdr := map[string]string{}
		for _, l := range lines[1:] {
			if k, val, ok := strings.Cut(l, ":"); ok {
				hdr[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(val)
			}
		}
		return &httpReply{status: status, headers: hdr, data: body}, true
	}
}
