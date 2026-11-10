package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/browser"
	"github.com/agardenat/clotr/internal/httpx"
	"github.com/agardenat/clotr/internal/i18n"
)

type LoginOptions struct {
	Path   string
	Role   string
	Port   int
	MinTTL time.Duration
	Wait   time.Duration
}

var TokenPath = func() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".vault-token")
}

type statusError struct {
	code int
	msg  string
}

func (e *statusError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.code, e.msg) }

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Addr+"/v1/"+path, rd)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("X-Vault-Token", c.Token)
	}
	if c.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.Namespace)
	}
	req.Header.Set("User-Agent", httpx.UserAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		msg := http.StatusText(resp.StatusCode)
		var e struct {
			Errors []string `json:"errors"`
		}
		if json.Unmarshal(data, &e) == nil && len(e.Errors) > 0 {
			msg = strings.Join(e.Errors, "; ")
		}
		return &statusError{code: resp.StatusCode, msg: msg}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

func (c *Client) lookupSelf(ctx context.Context) (time.Duration, bool, error) {
	var body struct {
		Data struct {
			TTL       int64 `json:"ttl"`
			Renewable bool  `json:"renewable"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "auth/token/lookup-self", nil, &body); err != nil {
		return 0, false, err
	}
	return time.Duration(body.Data.TTL) * time.Second, body.Data.Renewable, nil
}

func (c *Client) renewSelf(ctx context.Context) (time.Duration, error) {
	var body struct {
		Auth struct {
			LeaseDuration int64 `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := c.do(ctx, http.MethodPost, "auth/token/renew-self", map[string]any{}, &body); err != nil {
		return 0, err
	}
	return time.Duration(body.Auth.LeaseDuration) * time.Second, nil
}

func refused(err error) bool {
	var se *statusError
	return errors.As(err, &se) && (se.code == http.StatusForbidden || se.code == http.StatusUnauthorized || se.code == http.StatusBadRequest)
}

func EnsureLogin(ctx context.Context, o LoginOptions) error {
	if strings.TrimSpace(os.Getenv("VAULT_TOKEN")) != "" {
		return nil
	}
	addr := strings.TrimRight(strings.TrimSpace(os.Getenv("VAULT_ADDR")), "/")
	if addr == "" {
		return i18n.E("vault.addr")
	}
	c := &Client{Addr: addr, Namespace: strings.TrimSpace(os.Getenv("VAULT_NAMESPACE")), HTTP: &http.Client{Timeout: 30 * time.Second}}
	if b, err := os.ReadFile(TokenPath()); err == nil {
		c.Token = strings.TrimSpace(string(b))
	}
	if c.Token != "" {
		ttl, renewable, err := c.lookupSelf(ctx)
		switch {
		case err == nil && (ttl == 0 || ttl >= o.MinTTL):
			return nil
		case err == nil && renewable:
			if nt, err := c.renewSelf(ctx); err == nil && nt >= o.MinTTL {
				return nil
			}
		case err != nil && !refused(err):
			return err
		}
	}
	return c.loginOIDC(ctx, o)
}

func (c *Client) loginOIDC(ctx context.Context, o LoginOptions) error {
	c.Token = ""
	mount := strings.Trim(o.Path, "/")
	redirect := fmt.Sprintf("http://localhost:%d/oidc/callback", o.Port)
	nonce := rand.Text()
	var au struct {
		Data struct {
			AuthURL string `json:"auth_url"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodPost, "auth/"+mount+"/oidc/auth_url", map[string]any{"role": o.Role, "redirect_uri": redirect, "client_nonce": nonce}, &au); err != nil {
		return i18n.E("vault.login", mount, err)
	}
	if au.Data.AuthURL == "" {
		return i18n.E("vault.login_url", mount, redirect)
	}
	cb, err := browser.Listen(fmt.Sprintf("localhost:%d", o.Port), "/oidc/callback")
	if err != nil {
		return i18n.E("vault.login_listen", o.Port, err)
	}
	defer cb.Close()
	fmt.Fprintln(os.Stderr, i18n.T("vault.login_open", c.Addr, au.Data.AuthURL))
	browser.Open(au.Data.AuthURL)
	q, err := cb.Wait(ctx, o.Wait, func(q url.Values) string {
		if e := q.Get("error"); e != "" {
			return i18n.T("vault.login_page_err", e)
		}
		return i18n.T("vault.login_page_ok")
	})
	if errors.Is(err, browser.ErrTimeout) {
		return i18n.E("vault.login_timeout", o.Wait)
	}
	if err != nil {
		return err
	}
	if e := q.Get("error"); e != "" {
		return i18n.E("vault.login", mount, fmt.Errorf("%s %s", e, q.Get("error_description")))
	}
	v := url.Values{"state": {q.Get("state")}, "code": {q.Get("code")}, "client_nonce": {nonce}}
	if id := q.Get("id_token"); id != "" {
		v.Set("id_token", id)
	}
	var res struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := c.do(ctx, http.MethodGet, "auth/"+mount+"/oidc/callback?"+v.Encode(), nil, &res); err != nil {
		return i18n.E("vault.login", mount, err)
	}
	if res.Auth.ClientToken == "" {
		return i18n.E("vault.login", mount, errors.New("no client_token"))
	}
	p := TokenPath()
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(res.Auth.ClientToken), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
