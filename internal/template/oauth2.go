package template

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agardenat/clotr/internal/creds"
	"github.com/agardenat/clotr/internal/httpx"
	"github.com/agardenat/clotr/internal/i18n"
)

const oauthMargin = 2 * time.Minute

var oauthKeys = []string{"token_url", "vault", "client_id", "client_secret", "scope"}

var oauthField = regexp.MustCompile(`\{([A-Za-z0-9_.-]+)\}`)

type httpOAuth struct {
	tokenURL, vault, clientID, clientSecret, scope string

	mu       sync.Mutex
	resolved *oauthRequest
}

type oauthRequest struct {
	tokenURL string
	form     url.Values
	key      string
}

type oauthToken struct {
	value string
	exp   time.Time
}

type oauthState struct {
	mu     sync.Mutex
	tokens map[string]oauthToken
	fixed  string
}

func newHTTPOAuth(o options) *httpOAuth {
	if o.str("vault") == "" {
		return nil
	}
	return &httpOAuth{
		tokenURL:     o.str("token_url"),
		vault:        o.str("vault"),
		clientID:     defaultStr(o.str("client_id"), "{client_id}"),
		clientSecret: defaultStr(o.str("client_secret"), "{client_secret}"),
		scope:        o.str("scope"),
	}
}

func checkOAuthOptions(a options) error {
	o := a.sub("oauth2")
	for k := range a {
		if k != "oauth2" {
			return i18n.E("tpl.http.oauth_mixed", k)
		}
	}
	for k := range o {
		if !slices.Contains(oauthKeys, k) {
			return i18n.E("tpl.http.oauth_key", k)
		}
	}
	if o.str("vault") != "" && o.str("token_url") == "" {
		return i18n.E("tpl.http.oauth_url")
	}
	return nil
}

func (o *httpOAuth) request(ctx context.Context) (*oauthRequest, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.resolved != nil {
		return o.resolved, nil
	}
	path, _, _ := strings.Cut(o.vault, "#")
	fields := map[string]string{}
	var ferr error
	expand := func(s string) string {
		return oauthField.ReplaceAllStringFunc(s, func(m string) string {
			name := m[1 : len(m)-1]
			if v, ok := fields[name]; ok {
				return v
			}
			v, err := creds.ReadVault(ctx, path+"#"+name)
			if err != nil {
				if ferr == nil {
					ferr = i18n.E("tpl.http.oauth_vault", path, name, err)
				}
				return ""
			}
			fields[name] = v
			return v
		})
	}
	r := &oauthRequest{tokenURL: expand(o.tokenURL), form: url.Values{"grant_type": {"client_credentials"}}}
	r.form.Set("client_id", expand(o.clientID))
	r.form.Set("client_secret", expand(o.clientSecret))
	if scope := expand(o.scope); scope != "" {
		r.form.Set("scope", scope)
	}
	if ferr != nil {
		return nil, ferr
	}
	r.key = r.tokenURL + "\x00" + r.form.Get("client_id") + "\x00" + r.form.Get("scope")
	o.resolved = r
	return r, nil
}

func (in *Instance) oauthToken(ctx context.Context, hc *httpConn) (string, error) {
	st := &in.oauth
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.fixed != "" {
		return st.fixed, nil
	}
	r, err := hc.oauth.request(ctx)
	if err != nil {
		return "", err
	}
	if t, ok := st.tokens[r.key]; ok && in.now().Add(oauthMargin).Before(t.exp) {
		return t.value, nil
	}
	client, err := in.httpClient(hc)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(r.tokenURL)
	if err != nil || u.Host == "" {
		return "", i18n.E("tpl.http.oauth_invalid", r.tokenURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.tokenURL, strings.NewReader(r.form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", httpx.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		in.audit("http_oauth", map[string]any{"connector": hc.name, "host": u.Host, "error": err.Error()})
		return "", i18n.E("tpl.http.oauth_call", u.Host, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	in.audit("http_oauth", map[string]any{"connector": hc.name, "host": u.Host, "status": resp.StatusCode})
	var doc struct {
		AccessToken string          `json:"access_token"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
		Error       string          `json:"error"`
		Description string          `json:"error_description"`
	}
	_ = json.Unmarshal(body, &doc)
	if resp.StatusCode != http.StatusOK || doc.AccessToken == "" {
		msg := strings.TrimSpace(doc.Error + " " + doc.Description)
		if msg == "" {
			msg = httpx.Snippet(body, 300)
		}
		return "", i18n.E("tpl.http.oauth_refused", u.Host, resp.StatusCode, msg)
	}
	ttl, _ := strconv.Atoi(strings.Trim(string(doc.ExpiresIn), `"`))
	if ttl <= 0 {
		ttl = 3600
	}
	if st.tokens == nil {
		st.tokens = map[string]oauthToken{}
	}
	st.tokens[r.key] = oauthToken{value: doc.AccessToken, exp: in.now().Add(time.Duration(ttl) * time.Second)}
	return doc.AccessToken, nil
}
