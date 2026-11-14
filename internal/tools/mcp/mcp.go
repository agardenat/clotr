package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agardenat/clotr/internal/catalog"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/httpx"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/tools"
)

var invalidChars = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

const emptySchema = `{"type":"object","properties":{}}`

type Server struct {
	cfg     config.MCPServer
	session *sdk.ClientSession
	exposed []tools.Tool
	remotes map[string]bool
	skipped []string
}

func (s *Server) Name() string      { return s.cfg.Name }
func (s *Server) Skipped() []string { return s.skipped }
func (s *Server) Tools() []tools.Tool {
	return s.exposed
}

func (s *Server) Close() error {
	if s.session == nil {
		return nil
	}
	return s.session.Close()
}

type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("User-Agent", httpx.UserAgent)
	for k, v := range h.headers {
		r.Header.Set(k, v)
	}
	return h.base.RoundTrip(r)
}

func transport(cfg config.MCPServer) (sdk.Transport, error) {
	switch cfg.Transport {
	case "stdio":
		args := make([]string, len(cfg.Args))
		for i, a := range cfg.Args {
			args[i] = os.ExpandEnv(a)
		}
		cmd := exec.Command(cfg.Command, args...)
		cmd.Env = os.Environ()
		for k, v := range cfg.Env {
			cmd.Env = append(cmd.Env, k+"="+os.ExpandEnv(v))
		}
		cmd.Stderr = io.Discard
		return &sdk.CommandTransport{Command: cmd}, nil
	default:
		headers := map[string]string{}
		for k, v := range cfg.Headers {
			headers[k] = os.ExpandEnv(v)
		}
		hc := &http.Client{Transport: headerTransport{base: http.DefaultTransport, headers: headers}}
		endpoint := os.ExpandEnv(cfg.URL)
		if cfg.Transport == "sse" {
			return &sdk.SSEClientTransport{Endpoint: endpoint, HTTPClient: hc}, nil
		}
		t := &sdk.StreamableClientTransport{Endpoint: endpoint, HTTPClient: hc}
		if cfg.Auth == config.MCPAuthOAuth {
			h, err := newOAuthHandler(cfg.Name, endpoint)
			if err != nil {
				return nil, i18n.E("mcp.connect", cfg.Name, err)
			}
			t.OAuthHandler = h
		}
		return t, nil
	}
}

func Connect(ctx context.Context, cfg config.MCPServer, version string) (*Server, error) {
	t, err := transport(cfg)
	if err != nil {
		return nil, err
	}
	return ConnectTransport(ctx, cfg, t, version)
}

func ConnectTransport(ctx context.Context, cfg config.MCPServer, t sdk.Transport, version string) (*Server, error) {
	return connect(ctx, cfg, t, version, false)
}

func ConnectWriter(ctx context.Context, cfg config.MCPServer, version string) (*Server, error) {
	t, err := transport(cfg)
	if err != nil {
		return nil, err
	}
	return connect(ctx, cfg, t, version, true)
}

func ConnectWriterTransport(ctx context.Context, cfg config.MCPServer, t sdk.Transport, version string) (*Server, error) {
	return connect(ctx, cfg, t, version, true)
}

func connect(ctx context.Context, cfg config.MCPServer, t sdk.Transport, version string, writer bool) (*Server, error) {
	client := sdk.NewClient(&sdk.Implementation{Name: "clotr", Version: version}, nil)
	var cctx context.Context
	var cancel func()
	if cfg.Auth == config.MCPAuthOAuth {
		cctx, cancel = withStretch(ctx, cfg.Timeout.Duration)
	} else {
		cctx, cancel = context.WithTimeout(ctx, cfg.Timeout.Duration)
	}
	defer cancel()
	session, err := client.Connect(cctx, t, nil)
	if err != nil {
		return nil, i18n.E("mcp.connect", cfg.Name, err)
	}
	s := &Server{cfg: cfg, session: session, remotes: map[string]bool{}}
	allow := globs(cfg.Allow)
	deny := globs(cfg.Deny)
	names := map[string]bool{}
	for t, err := range session.Tools(cctx, nil) {
		if err != nil {
			_ = session.Close()
			return nil, fmt.Errorf("mcp %s: tools/list: %w", cfg.Name, err)
		}
		readOnly := t.Annotations != nil && t.Annotations.ReadOnlyHint
		if matchAny(deny, t.Name) || (!writer && !readOnly && !matchAny(allow, t.Name)) {
			s.skipped = append(s.skipped, t.Name)
			continue
		}
		nt := newTool(s, t)
		if names[nt.name] {
			s.skipped = append(s.skipped, t.Name+i18n.T("mcp.collision"))
			continue
		}
		names[nt.name] = true
		s.remotes[t.Name] = true
		s.exposed = append(s.exposed, nt)
	}
	return s, nil
}

func globs(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, catalog.Glob(p))
	}
	return out
}

func matchAny(res []*regexp.Regexp, name string) bool {
	for _, re := range res {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

type tool struct {
	srv    *Server
	remote string
	name   string
	desc   string
	schema json.RawMessage
}

func ToolName(server, remote string) string {
	n := "mcp_" + server + "_" + invalidChars.ReplaceAllString(remote, "_")
	if len(n) > 64 {
		n = n[:64]
	}
	return n
}

func newTool(s *Server, t *sdk.Tool) *tool {
	schema := json.RawMessage(emptySchema)
	if t.InputSchema != nil {
		if b, err := json.Marshal(t.InputSchema); err == nil && string(b) != "null" {
			schema = b
		}
	}
	desc := strings.TrimSpace(t.Description)
	if desc == "" {
		desc = t.Title
	}
	return &tool{srv: s, remote: t.Name, name: ToolName(s.cfg.Name, t.Name), desc: fmt.Sprintf("[MCP %s] %s", s.cfg.Name, desc), schema: schema}
}

func (t *tool) Name() string            { return t.name }
func (t *tool) Description() string     { return t.desc }
func (t *tool) Schema() json.RawMessage { return t.schema }

func (t *tool) Call(ctx context.Context, args json.RawMessage) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, t.srv.cfg.Timeout.Duration)
	defer cancel()
	var params any = map[string]any{}
	if len(args) > 0 {
		params = args
	}
	res, err := t.srv.session.CallTool(cctx, &sdk.CallToolParams{Name: t.remote, Arguments: params})
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, c := range res.Content {
		switch v := c.(type) {
		case *sdk.TextContent:
			b.WriteString(v.Text)
			b.WriteString("\n")
		default:
			fmt.Fprintf(&b, "[contenu %T non textuel omis]\n", c)
		}
	}
	if b.Len() == 0 && res.StructuredContent != nil {
		data, _ := json.Marshal(res.StructuredContent)
		b.Write(data)
	}
	if res.IsError {
		return "", errors.New(strings.TrimSpace(b.String()))
	}
	return b.String(), nil
}

func (s *Server) Fetch(ctx context.Context, raw string, maxBytes int64) ([]byte, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, i18n.E("mcp.fetch_url", s.cfg.Name, truncate(raw, 60))
	}
	own := false
	if base, err := url.Parse(os.ExpandEnv(s.cfg.URL)); err == nil && s.cfg.URL != "" {
		own = base.Scheme == u.Scheme && base.Host == u.Host
	}
	if u.Scheme != "https" && !own {
		return nil, i18n.E("mcp.fetch_url", s.cfg.Name, u.Redacted())
	}
	cctx, cancel := context.WithTimeout(ctx, max(s.cfg.Timeout.Duration, time.Minute))
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpx.UserAgent)
	if own {
		for k, v := range s.cfg.Headers {
			req.Header.Set(k, os.ExpandEnv(v))
		}
	}
	client := &http.Client{CheckRedirect: func(r *http.Request, _ []*http.Request) error {
		if r.URL.Host != u.Host {
			for k := range s.cfg.Headers {
				r.Header.Del(k)
			}
		}
		return nil
	}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, i18n.E("mcp.fetch", s.cfg.Name, u.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, i18n.E("mcp.fetch_status", s.cfg.Name, u.Host, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, i18n.E("mcp.fetch", s.cfg.Name, u.Host, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, i18n.E("mcp.fetch_size", s.cfg.Name, maxBytes>>20)
	}
	return data, nil
}

func ConnectAll(ctx context.Context, cfgs []config.MCPServer, version string) ([]*Server, []string) {
	return connectAll(ctx, cfgs, version, true)
}

func ConnectForTemplates(ctx context.Context, cfgs []config.MCPServer, version string) ([]*Server, []string) {
	return connectAll(ctx, cfgs, version, false)
}

func connectAll(ctx context.Context, cfgs []config.MCPServer, version string, exposed bool) ([]*Server, []string) {
	servers := make([]*Server, len(cfgs))
	errs := make([]error, len(cfgs))
	var wg sync.WaitGroup
	for i, c := range cfgs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			servers[i], errs[i] = Connect(ctx, c, version)
		}()
	}
	wg.Wait()
	var ok []*Server
	var warnings []string
	for i, s := range servers {
		if errs[i] != nil {
			warnings = append(warnings, errs[i].Error())
			continue
		}
		if n := len(s.skipped); n > 0 && exposed {
			shown := s.skipped
			more := ""
			if n > 5 {
				shown, more = shown[:5], fmt.Sprintf(", … (+%d, voir clotr tools)", n-5)
			}
			warnings = append(warnings, i18n.T("mcp.unexposed", s.cfg.Name, n, strings.Join(shown, ", "), more))
		}
		ok = append(ok, s)
	}
	return ok, warnings
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (s *Server) CallExposed(ctx context.Context, remote string, args map[string]any) (string, json.RawMessage, bool, error) {
	if !s.remotes[remote] {
		return "", nil, false, i18n.E("mcp.not_exposed", s.cfg.Name, remote)
	}
	cctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout.Duration)
	defer cancel()
	if args == nil {
		args = map[string]any{}
	}
	res, err := s.session.CallTool(cctx, &sdk.CallToolParams{Name: remote, Arguments: args})
	if err != nil {
		return "", nil, false, err
	}
	var b strings.Builder
	for _, c := range res.Content {
		if v, ok := c.(*sdk.TextContent); ok {
			b.WriteString(v.Text)
		}
	}
	var data json.RawMessage
	if res.StructuredContent != nil {
		if data, err = json.Marshal(res.StructuredContent); err != nil {
			return "", nil, false, err
		}
	}
	return b.String(), data, res.IsError, nil
}
