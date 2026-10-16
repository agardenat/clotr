package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/httpx"
	"github.com/agardenat/clotr/internal/i18n"
)

type ModelInfo struct {
	Provider   string  `json:"provider"`
	ID         string  `json:"id"`
	Tier       string  `json:"tier"`
	Context    int     `json:"context"`
	Tools      bool    `json:"tools"`
	Priority   int     `json:"priority"`
	Weight     int     `json:"weight"`
	Sovereign  bool    `json:"sovereign"`
	MaxOutput  int     `json:"max_output,omitempty"`
	Source     string  `json:"source"`
	InputCost  float64 `json:"input_cost_per_token,omitempty"`
	OutputCost float64 `json:"output_cost_per_token,omitempty"`
}

func (m ModelInfo) Score() int {
	return m.Weight + m.Priority
}

func (m ModelInfo) Ref() string {
	return m.Provider + "/" + m.ID
}

func SplitRef(ref string) (string, string, bool) {
	p, m, ok := strings.Cut(ref, "/")
	if !ok || p == "" || m == "" {
		return "", "", false
	}
	return p, m, true
}

type RawModel struct {
	ID         string  `json:"id"`
	Context    int     `json:"context,omitempty"`
	MaxOutput  int     `json:"max_output,omitempty"`
	Tools      *bool   `json:"tools,omitempty"`
	InputCost  float64 `json:"input_cost_per_token,omitempty"`
	OutputCost float64 `json:"output_cost_per_token,omitempty"`
}

type Snapshot struct {
	Provider string     `json:"provider"`
	Models   []RawModel `json:"models"`
	Error    string     `json:"error,omitempty"`
}

type cacheFile struct {
	Key       string     `json:"key"`
	FetchedAt time.Time  `json:"fetched_at"`
	Snapshots []Snapshot `json:"snapshots"`
}

type Catalog struct {
	Models    []ModelInfo
	Warnings  []string
	FetchedAt time.Time
	FromCache bool
}

func (c *Catalog) Find(ref string) (ModelInfo, bool) {
	for _, m := range c.Models {
		if m.Ref() == ref {
			return m, true
		}
	}
	return ModelInfo{}, false
}

func DefaultCachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "clotr", "catalog.json")
}

func Load(ctx context.Context, cfg *config.Config, hc *http.Client, cachePath string, refresh bool) (*Catalog, error) {
	key := cacheKey(cfg)
	if !refresh && cachePath != "" {
		if cf, err := readCache(cachePath); err == nil && cf.Key == key && time.Since(cf.FetchedAt) < cfg.Catalog.CacheTTL.Duration {
			cat := Build(cfg, cf.Snapshots)
			cat.FetchedAt = cf.FetchedAt
			cat.FromCache = true
			return cat, nil
		}
	}
	snaps := Discover(ctx, cfg, hc)
	failed := 0
	for _, s := range snaps {
		if s.Error != "" {
			failed++
		}
	}
	if failed == len(snaps) {
		var errs []error
		for _, s := range snaps {
			errs = append(errs, fmt.Errorf("%s: %s", s.Provider, s.Error))
		}
		return nil, i18n.E("catalog.unreachable", errors.Join(errs...))
	}
	now := time.Now()
	if failed == 0 && cachePath != "" {
		_ = writeCache(cachePath, cacheFile{Key: key, FetchedAt: now, Snapshots: snaps})
	}
	cat := Build(cfg, snaps)
	cat.FetchedAt = now
	return cat, nil
}

func Discover(ctx context.Context, cfg *config.Config, hc *http.Client) []Snapshot {
	snaps := make([]Snapshot, len(cfg.Providers))
	var wg sync.WaitGroup
	for i, p := range cfg.Providers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snaps[i] = discoverProvider(ctx, hc, p)
		}()
	}
	wg.Wait()
	return snaps
}

func discoverProvider(ctx context.Context, hc *http.Client, p config.Provider) Snapshot {
	s := Snapshot{Provider: p.Name}
	var list struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := getJSON(ctx, hc, p, p.BaseURL+"/models", &list); err != nil {
		s.Error = err.Error()
		return s
	}
	info := map[string]RawModel{}
	if p.ModelInfo {
		info = litellmModelInfo(ctx, hc, p)
	}
	for _, d := range list.Data {
		m := RawModel{ID: d.ID}
		if i, ok := info[d.ID]; ok {
			m.Context, m.MaxOutput = i.Context, i.MaxOutput
			m.Tools = i.Tools
			m.InputCost, m.OutputCost = i.InputCost, i.OutputCost
		}
		s.Models = append(s.Models, m)
	}
	return s
}

func litellmModelInfo(ctx context.Context, hc *http.Client, p config.Provider) map[string]RawModel {
	var resp struct {
		Data []struct {
			ModelName string `json:"model_name"`
			ModelInfo struct {
				MaxInputTokens          int     `json:"max_input_tokens"`
				MaxOutputTokens         int     `json:"max_output_tokens"`
				SupportsFunctionCalling *bool   `json:"supports_function_calling"`
				InputCostPerToken       float64 `json:"input_cost_per_token"`
				OutputCostPerToken      float64 `json:"output_cost_per_token"`
			} `json:"model_info"`
		} `json:"data"`
	}
	urls := []string{p.BaseURL + "/model/info"}
	if trimmed, ok := strings.CutSuffix(p.BaseURL, "/v1"); ok {
		urls = append(urls, trimmed+"/model/info")
	}
	out := map[string]RawModel{}
	for _, u := range urls {
		if err := getJSON(ctx, hc, p, u, &resp); err != nil {
			continue
		}
		for _, d := range resp.Data {
			out[d.ModelName] = RawModel{ID: d.ModelName, Context: d.ModelInfo.MaxInputTokens, MaxOutput: d.ModelInfo.MaxOutputTokens, Tools: d.ModelInfo.SupportsFunctionCalling, InputCost: d.ModelInfo.InputCostPerToken, OutputCost: d.ModelInfo.OutputCostPerToken}
		}
		break
	}
	return out
}

func getJSON(ctx context.Context, hc *http.Client, p config.Provider, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", httpx.UserAgent)
	if key := p.APIKey(); key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET %s: HTTP %d: %s", url, resp.StatusCode, httpx.Snippet(body, 300))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type compiledProfile struct {
	config.Profile
	re *regexp.Regexp
}

func compileProfiles(ps []config.Profile) []compiledProfile {
	out := make([]compiledProfile, 0, len(ps))
	for _, p := range ps {
		out = append(out, compiledProfile{Profile: p, re: Glob(p.Match)})
	}
	return out
}

func Glob(pattern string) *regexp.Regexp {
	q := regexp.QuoteMeta(pattern)
	q = strings.ReplaceAll(q, `\*`, ".*")
	q = strings.ReplaceAll(q, `\?`, ".")
	return regexp.MustCompile("(?i)^" + q + "$")
}

func Build(cfg *config.Config, snaps []Snapshot) *Catalog {
	cat := &Catalog{}
	profiles := compileProfiles(cfg.Profiles)
	order := map[string]int{}
	provs := map[string]config.Provider{}
	for i, p := range cfg.Providers {
		order[p.Name] = i
		provs[p.Name] = p
	}
	var unprofiled []string
	for _, s := range snaps {
		if s.Error != "" {
			cat.Warnings = append(cat.Warnings, i18n.T("catalog.provider_down", s.Provider, s.Error))
			continue
		}
		for _, raw := range s.Models {
			prov := provs[s.Provider]
			m := ModelInfo{Provider: s.Provider, ID: raw.ID, Tier: "balanced", Context: raw.Context, MaxOutput: raw.MaxOutput, Source: "default", Weight: prov.Weight, Sovereign: prov.Sovereign, InputCost: raw.InputCost, OutputCost: raw.OutputCost}
			if raw.Tools != nil {
				m.Tools = *raw.Tools
			}
			if raw.Context > 0 || raw.Tools != nil {
				m.Source = "model_info"
			}
			prof, ok := matchProfile(profiles, m)
			if ok {
				if prof.Exclude {
					continue
				}
				m.Source = "profile"
				if prof.Tier != "" {
					m.Tier = prof.Tier
				}
				if prof.Context > 0 {
					m.Context = prof.Context
				}
				if prof.Tools != nil {
					m.Tools = *prof.Tools
				}
				m.Priority = prof.Priority
				if prof.Sovereign != nil {
					m.Sovereign = *prof.Sovereign
				}
			} else {
				unprofiled = append(unprofiled, m.Ref())
			}
			cat.Models = append(cat.Models, m)
		}
	}
	if len(unprofiled) > 0 {
		shown := unprofiled
		suffix := ""
		if len(shown) > 5 {
			shown, suffix = shown[:5], i18n.T("catalog.more", len(unprofiled)-5)
		}
		cat.Warnings = append(cat.Warnings, i18n.T("catalog.unprofiled", len(unprofiled), strings.Join(shown, ", "), suffix))
	}
	sort.SliceStable(cat.Models, func(i, j int) bool {
		a, b := cat.Models[i], cat.Models[j]
		if order[a.Provider] != order[b.Provider] {
			return order[a.Provider] < order[b.Provider]
		}
		return a.ID < b.ID
	})
	return cat
}

func matchProfile(ps []compiledProfile, m ModelInfo) (config.Profile, bool) {
	for _, p := range ps {
		if p.re.MatchString(m.ID) || p.re.MatchString(m.Ref()) {
			return p.Profile, true
		}
	}
	return config.Profile{}, false
}

func cacheKey(cfg *config.Config) string {
	var b strings.Builder
	b.WriteString("v2|")
	for _, p := range cfg.Providers {
		fmt.Fprintf(&b, "%s=%s;%t|", p.Name, p.BaseURL, p.ModelInfo)
	}
	return b.String()
}

func readCache(path string) (*cacheFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cf cacheFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, err
	}
	return &cf, nil
}

func writeCache(path string, cf cacheFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cf, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
