package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"

	"github.com/agardenat/clotr/internal/browser"
	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/httpx"
	"github.com/agardenat/clotr/internal/i18n"
)

const loginWait = 5 * time.Minute

var loginsClosed atomic.Bool

func CloseLogins() {
	loginsClosed.Store(true)
}

func Login(ctx context.Context, cfg config.MCPServer, version string) error {
	if cfg.Auth != config.MCPAuthOAuth {
		return nil
	}
	s, err := Connect(ctx, cfg, version)
	if err != nil {
		return err
	}
	return s.Close()
}

var oauthDir = func() string { return filepath.Join(config.StateDir(), "clotr", "oauth") }

type oauthTransport struct {
	base    http.RoundTripper
	host    string
	headers map[string]string
	mu      sync.Mutex
	methods []string
	reg     string
}

func newOAuthClient(endpoint string, headers map[string]string) *http.Client {
	host := ""
	if u, err := url.Parse(endpoint); err == nil {
		host = u.Host
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &oauthTransport{base: http.DefaultTransport, host: host, headers: headers}}
}

func (t *oauthTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("User-Agent", httpx.UserAgent)
	if r.URL.Host == t.host {
		for k, v := range t.headers {
			if !strings.EqualFold(k, "Authorization") {
				r.Header.Set(k, v)
			}
		}
	}
	resp, err := t.base.RoundTrip(r)
	if err != nil || resp.StatusCode/100 != 2 {
		return resp, err
	}
	meta := strings.Contains(r.URL.Path, "/.well-known/oauth-authorization-server") || strings.Contains(r.URL.Path, "/.well-known/openid-configuration")
	t.mu.Lock()
	reg := r.Method == http.MethodPost && t.reg != "" && r.URL.String() == t.reg
	methods := t.methods
	t.mu.Unlock()
	if !meta && !reg {
		return resp, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if meta {
		var m struct {
			Methods []string `json:"token_endpoint_auth_methods_supported"`
			Reg     string   `json:"registration_endpoint"`
		}
		if json.Unmarshal(body, &m) == nil {
			t.mu.Lock()
			t.methods, t.reg = m.Methods, m.Reg
			t.mu.Unlock()
		}
	} else {
		body = registrationAuthMethod(body, methods)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return resp, nil
}

func registrationAuthMethod(body []byte, supported []string) []byte {
	if len(supported) == 0 || slices.Contains(supported, "client_secret_basic") {
		return body
	}
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return body
	}
	if v, _ := m["token_endpoint_auth_method"].(string); v != "" {
		return body
	}
	for _, method := range []string{"client_secret_post", "none"} {
		if slices.Contains(supported, method) {
			m["token_endpoint_auth_method"] = method
			if b, err := json.Marshal(m); err == nil {
				return b
			}
			break
		}
	}
	return body
}

type oauthCache struct {
	URL          string           `json:"url"`
	ClientID     string           `json:"client_id"`
	ClientSecret string           `json:"client_secret,omitempty"`
	RedirectURL  string           `json:"redirect_url"`
	TokenURL     string           `json:"token_url"`
	AuthStyle    oauth2.AuthStyle `json:"auth_style"`
	Token        *oauth2.Token    `json:"token,omitempty"`
}

type oauthStore struct {
	path string
	mu   sync.Mutex
	data oauthCache
}

func loadStore(name, endpoint string) *oauthStore {
	s := &oauthStore{path: filepath.Join(oauthDir(), name+".json")}
	if b, err := os.ReadFile(s.path); err == nil {
		var c oauthCache
		if json.Unmarshal(b, &c) == nil && c.URL == endpoint && c.ClientID != "" && c.RedirectURL != "" {
			s.data = c
		}
	}
	s.data.URL = endpoint
	return s
}

func (s *oauthStore) saveLocked() {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, s.path)
}

func (s *oauthStore) setClient(c *oauth2.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.ClientID = c.ClientID
	s.data.ClientSecret = c.ClientSecret
	s.data.RedirectURL = c.RedirectURL
	s.data.TokenURL = c.Endpoint.TokenURL
	s.data.AuthStyle = c.Endpoint.AuthStyle
}

func (s *oauthStore) setToken(t *oauth2.Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Token != nil && s.data.Token.AccessToken == t.AccessToken && s.data.Token.RefreshToken == t.RefreshToken {
		return
	}
	s.data.Token = t
	s.saveLocked()
}

var errRefreshRefused = &oauth2.RetrieveError{ErrorCode: "invalid_grant", ErrorDescription: "refresh grant refused by the authorization server"}

type savingSource struct {
	base    oauth2.TokenSource
	store   *oauthStore
	refused atomic.Bool
}

func (s *savingSource) Token() (*oauth2.Token, error) {
	if s.refused.Load() {
		return nil, errRefreshRefused
	}
	t, err := s.base.Token()
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && grantError(re) == "unsupported_grant_type" {
			s.refused.Store(true)
			return nil, errRefreshRefused
		}
		return nil, err
	}
	s.store.setToken(t)
	return t, nil
}

func grantError(re *oauth2.RetrieveError) string {
	if re.ErrorCode != "" {
		return re.ErrorCode
	}
	var body struct {
		Detail struct {
			Error string `json:"error"`
		} `json:"detail"`
	}
	if json.Unmarshal(re.Body, &body) == nil {
		return body.Detail.Error
	}
	return ""
}

func refreshContext(client *http.Client) context.Context {
	return context.WithValue(context.Background(), oauth2.HTTPClient, client)
}

func newOAuthHandler(name, endpoint string, headers map[string]string) (auth.OAuthHandler, error) {
	store := loadStore(name, endpoint)
	c := store.data
	client := newOAuthClient(endpoint, headers)
	hcfg := &auth.AuthorizationCodeHandlerConfig{
		Client:              client,
		RequestRefreshToken: true,
		NewTokenSource: func(ctx context.Context, oc *oauth2.Config, tok *oauth2.Token) (oauth2.TokenSource, error) {
			store.setClient(oc)
			src := &savingSource{base: oc.TokenSource(refreshContext(client), tok), store: store}
			if _, err := src.Token(); err != nil {
				return nil, err
			}
			return src, nil
		},
	}
	if c.ClientID != "" {
		pre := &oauthex.ClientCredentials{ClientID: c.ClientID}
		if c.ClientSecret != "" {
			pre.ClientSecretAuth = &oauthex.ClientSecretAuth{ClientSecret: c.ClientSecret}
		}
		hcfg.PreregisteredClient = pre
		hcfg.RedirectURL = c.RedirectURL
		if c.Token != nil && c.TokenURL != "" {
			oc := &oauth2.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, Endpoint: oauth2.Endpoint{TokenURL: c.TokenURL, AuthStyle: c.AuthStyle}}
			hcfg.InitialTokenSource = &savingSource{base: oc.TokenSource(refreshContext(client), c.Token), store: store}
		}
	} else {
		port, err := freePort()
		if err != nil {
			return nil, err
		}
		hcfg.RedirectURL = fmt.Sprintf("http://127.0.0.1:%d/callback", port)
		hcfg.DynamicClientRegistrationConfig = &auth.DynamicClientRegistrationConfig{Metadata: &oauthex.ClientRegistrationMetadata{
			RedirectURIs:            []string{hcfg.RedirectURL},
			TokenEndpointAuthMethod: "none",
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			ResponseTypes:           []string{"code"},
			ClientName:              "clotr",
		}}
	}
	hcfg.AuthorizationCodeFetcher = browserFetcher(name, hcfg.RedirectURL)
	return auth.NewAuthorizationCodeHandler(hcfg)
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

type stretchKey struct{}

type stretcher struct {
	timer *time.Timer
	base  time.Duration
}

func withStretch(ctx context.Context, d time.Duration) (context.Context, func()) {
	cctx, cancel := context.WithCancelCause(ctx)
	st := &stretcher{base: d}
	st.timer = time.AfterFunc(d, func() { cancel(context.DeadlineExceeded) })
	return context.WithValue(cctx, stretchKey{}, st), func() {
		st.timer.Stop()
		cancel(context.Canceled)
	}
}

func stretch(ctx context.Context, d time.Duration) func() {
	st, _ := ctx.Value(stretchKey{}).(*stretcher)
	if st == nil {
		return func() {}
	}
	st.timer.Reset(d)
	return func() { st.timer.Reset(st.base) }
}

func browserFetcher(name, redirect string) auth.AuthorizationCodeFetcher {
	return func(ctx context.Context, a *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
		if loginsClosed.Load() {
			return nil, i18n.E("mcp.oauth_closed", name)
		}
		ru, err := url.Parse(redirect)
		if err != nil {
			return nil, err
		}
		cb, err := browser.Listen(ru.Host, ru.Path)
		if err != nil {
			return nil, i18n.E("mcp.oauth_listen", name, ru.Host, err, filepath.Join(oauthDir(), name+".json"))
		}
		defer cb.Close()
		restore := stretch(ctx, loginWait+time.Minute)
		defer restore()
		fmt.Fprintln(os.Stderr, i18n.T("mcp.oauth_login", name, a.URL))
		browser.Open(a.URL)
		q, err := cb.Wait(ctx, loginWait, func(q url.Values) string {
			if e := q.Get("error"); e != "" {
				return i18n.T("mcp.oauth_page_err", e)
			}
			return i18n.T("mcp.oauth_page_ok")
		})
		if errors.Is(err, browser.ErrTimeout) {
			return nil, i18n.E("mcp.oauth_timeout", name, loginWait)
		}
		if err != nil {
			return nil, err
		}
		if e := q.Get("error"); e != "" {
			return nil, i18n.E("mcp.oauth_denied", name, e, q.Get("error_description"))
		}
		return &auth.AuthorizationResult{Code: q.Get("code"), State: q.Get("state"), Iss: q.Get("iss")}, nil
	}
}
