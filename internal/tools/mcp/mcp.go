package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/agardenat/clotr/internal/catalog"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/httpx"
	"github.com/agardenat/clotr/internal/tools"
)

var invalidChars = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

const emptySchema = `{"type":"object","properties":{}}`

type Server struct {
	cfg     config.MCPServer
	session *sdk.ClientSession
	exposed []tools.Tool
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

func transport(cfg config.MCPServer) sdk.Transport {
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
		return &sdk.CommandTransport{Command: cmd}
	default:
		headers := map[string]string{}
		for k, v := range cfg.Headers {
			headers[k] = os.ExpandEnv(v)
		}
		hc := &http.Client{Transport: headerTransport{base: http.DefaultTransport, headers: headers}}
		if cfg.Transport == "sse" {
			return &sdk.SSEClientTransport{Endpoint: os.ExpandEnv(cfg.URL), HTTPClient: hc}
		}
		return &sdk.StreamableClientTransport{Endpoint: os.ExpandEnv(cfg.URL), HTTPClient: hc}
	}
}

func Connect(ctx context.Context, cfg config.MCPServer, version string) (*Server, error) {
	return ConnectTransport(ctx, cfg, transport(cfg), version)
}

func ConnectTransport(ctx context.Context, cfg config.MCPServer, t sdk.Transport, version string) (*Server, error) {
	client := sdk.NewClient(&sdk.Implementation{Name: "clotr", Version: version}, nil)
	cctx, cancel := context.WithTimeout(ctx, cfg.Timeout.Duration)
	defer cancel()
	session, err := client.Connect(cctx, t, nil)
	if err != nil {
		return nil, fmt.Errorf("mcp %s: connexion: %w", cfg.Name, err)
	}
	s := &Server{cfg: cfg, session: session}
	allow := globs(cfg.Allow)
	deny := globs(cfg.Deny)
	names := map[string]bool{}
	for t, err := range session.Tools(cctx, nil) {
		if err != nil {
			_ = session.Close()
			return nil, fmt.Errorf("mcp %s: tools/list: %w", cfg.Name, err)
		}
		readOnly := t.Annotations != nil && t.Annotations.ReadOnlyHint
		if matchAny(deny, t.Name) || (!readOnly && !matchAny(allow, t.Name)) {
			s.skipped = append(s.skipped, t.Name)
			continue
		}
		nt := newTool(s, t)
		if names[nt.name] {
			s.skipped = append(s.skipped, t.Name+" (nom en collision après normalisation)")
			continue
		}
		names[nt.name] = true
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

func ConnectAll(ctx context.Context, cfgs []config.MCPServer, version string) ([]*Server, []string) {
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
		if n := len(s.skipped); n > 0 {
			shown := s.skipped
			more := ""
			if n > 5 {
				shown, more = shown[:5], fmt.Sprintf(", … (+%d, voir clotr tools)", n-5)
			}
			warnings = append(warnings, fmt.Sprintf("mcp %s: %d outils non exposés (ni readOnlyHint ni allow): %s%s", s.cfg.Name, n, strings.Join(shown, ", "), more))
		}
		ok = append(ok, s)
	}
	return ok, warnings
}
