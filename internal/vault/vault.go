package vault

import (
	"context"
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

	"github.com/agardenat/clotr/internal/httpx"
)

type Client struct {
	Addr      string
	Token     string
	Namespace string
	HTTP      *http.Client
}

func FromEnv() (*Client, error) {
	addr := strings.TrimRight(strings.TrimSpace(os.Getenv("VAULT_ADDR")), "/")
	if addr == "" {
		return nil, errors.New("VAULT_ADDR non défini")
	}
	token := strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
	if token == "" {
		if home, err := os.UserHomeDir(); err == nil {
			if b, err := os.ReadFile(filepath.Join(home, ".vault-token")); err == nil {
				token = strings.TrimSpace(string(b))
			}
		}
	}
	if token == "" {
		return nil, errors.New("aucun jeton (VAULT_TOKEN ou ~/.vault-token, voir vault login)")
	}
	return &Client{Addr: addr, Token: token, Namespace: strings.TrimSpace(os.Getenv("VAULT_NAMESPACE")), HTTP: &http.Client{Timeout: 30 * time.Second}}, nil
}

func Secret(ctx context.Context, ref string) (string, error) {
	c, err := FromEnv()
	if err != nil {
		return "", err
	}
	return c.Read(ctx, ref)
}

func (c *Client) Read(ctx context.Context, ref string) (string, error) {
	path, field, _ := strings.Cut(ref, "#")
	path = strings.Trim(strings.TrimSpace(path), "/")
	field = strings.TrimSpace(field)
	if field == "" {
		field = "password"
	}
	if path == "" {
		return "", errors.New("référence vide")
	}
	api := path
	if mount, version, err := c.mount(ctx, path); err == nil && version == "2" && strings.HasPrefix(path+"/", mount) {
		api = mount + "data/" + strings.TrimPrefix(path, mount)
	}
	var body struct {
		Data map[string]any `json:"data"`
	}
	if err := c.get(ctx, api, &body); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	data := body.Data
	if inner, ok := data["data"].(map[string]any); ok {
		if _, v2 := data["metadata"]; v2 {
			data = inner
		}
	}
	v, ok := data[field]
	if !ok {
		return "", fmt.Errorf("%s: champ %q absent", path, field)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("%s: champ %q vide ou non textuel", path, field)
	}
	return s, nil
}

func (c *Client) mount(ctx context.Context, path string) (string, string, error) {
	var body struct {
		Data struct {
			Path    string            `json:"path"`
			Options map[string]string `json:"options"`
		} `json:"data"`
	}
	if err := c.get(ctx, "sys/internal/ui/mounts/"+path, &body); err != nil {
		return "", "", err
	}
	return body.Data.Path, body.Data.Options["version"], nil
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Addr+"/v1/"+strings.Join(segs, "/"), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", c.Token)
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
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
	}
	return json.Unmarshal(data, out)
}
