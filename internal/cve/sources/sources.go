package sources

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/httpx"
)

const (
	CVEOrg = "cveorg"
	NVD    = "nvd"
	KEV    = "kev"
	EPSS   = "epss"
	GitHub = "github"
	RedHat = "redhat"
	Ubuntu = "ubuntu"
	Debian = "debian"

	StateOK     = "ok"
	StateAbsent = "absent"
	StateError  = "error"

	ToolName = "cve_source"
)

var (
	Distros = []string{RedHat, Ubuntu, Debian}
	order   = []string{CVEOrg, NVD, KEV, EPSS, GitHub, RedHat, Ubuntu, Debian}
	cveRe   = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	ghsaRe  = regexp.MustCompile(`^GHSA(-[0-9a-z]{4}){3}$`)
)

var urls = map[string]string{
	CVEOrg: "https://cveawg.mitre.org/api/cve/%s",
	NVD:    "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s",
	KEV:    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
	EPSS:   "https://api.first.org/data/v1/epss?cve=%s",
	GitHub: "https://api.github.com/advisories?cve_id=%s",
	RedHat: "https://access.redhat.com/hydra/rest/securitydata/cve/%s.json",
	Ubuntu: "https://ubuntu.com/security/cves/%s.json",
	Debian: "https://api.osv.dev/v1/vulns/DEBIAN-%s",
}

const ghsaURL = "https://api.github.com/advisories/%s"

func Known(name string) bool { return slices.Contains(Distros, name) }

func Official(id string) bool { return cveRe.MatchString(id) || ghsaRe.MatchString(id) }

type Getter func(ctx context.Context, url string) (int, []byte, error)

type Client struct {
	Get      Getter
	Distros  []string
	CacheDir string
	KEVTTL   time.Duration
	Now      func() time.Time
	Retries  []time.Duration
}

func New(distros []string, cacheDir string) *Client {
	if len(distros) == 0 {
		distros = Distros
	}
	return &Client{Get: httpGet(&http.Client{Timeout: 45 * time.Second}), Distros: distros, CacheDir: cacheDir, KEVTTL: 6 * time.Hour, Now: time.Now, Retries: []time.Duration{2 * time.Second, 6 * time.Second}}
}

func httpGet(c *http.Client) Getter {
	return func(ctx context.Context, url string) (int, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("User-Agent", httpx.UserAgent)
		req.Header.Set("Accept", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		return resp.StatusCode, body, err
	}
}

type Record func(source, url, body string, err error) string

type response struct {
	status int
	body   []byte
	err    error
}

func (c *Client) fetch(ctx context.Context, url string) response {
	var r response
	for i := 0; ; i++ {
		r.status, r.body, r.err = c.Get(ctx, url)
		retry := r.err != nil || r.status == http.StatusTooManyRequests || r.status >= 500
		if !retry || i >= len(c.Retries) || ctx.Err() != nil {
			return r
		}
		select {
		case <-ctx.Done():
			return r
		case <-time.After(c.Retries[i]):
		}
	}
}

func (c *Client) Collect(ctx context.Context, id string, record Record) *Facts {
	f := &Facts{ID: id}
	cve := id
	if ghsaRe.MatchString(id) {
		url := fmt.Sprintf(ghsaURL, id)
		r := c.fetch(ctx, url)
		src := Source{Name: GitHub, URL: url}
		part, state, err := c.parse(GitHub, r)
		src.State, src.Error = state, errText(err)
		src.Evidence = record(GitHub, url, string(r.body), err)
		if part != nil {
			src.Hash = part.hash()
			f.merge(part)
			cve = part.CVE
		}
		f.Sources = append(f.Sources, src)
		if cve == "" {
			return f
		}
		f.CVE = cve
	}
	for _, name := range order {
		if ctx.Err() != nil {
			return f
		}
		if name == GitHub && f.has(GitHub) {
			continue
		}
		if slices.Contains(Distros, name) && !slices.Contains(c.Distros, name) {
			continue
		}
		f.Sources = append(f.Sources, c.collectOne(ctx, name, cve, f, record))
	}
	return f
}

func (c *Client) collectOne(ctx context.Context, name, cve string, f *Facts, record Record) Source {
	if name == KEV {
		return c.collectKEV(ctx, cve, f, record)
	}
	url := fmt.Sprintf(urls[name], cve)
	r := c.fetch(ctx, url)
	src := Source{Name: name, URL: url}
	part, state, err := c.parse(name, r)
	src.State, src.Error = state, errText(err)
	src.Evidence = record(name, url, string(r.body), err)
	if part != nil {
		if name != EPSS {
			src.Hash = part.hash()
		}
		f.merge(part)
	}
	return src
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (c *Client) parse(name string, r response) (*Facts, string, error) {
	if r.err != nil {
		return nil, StateError, r.err
	}
	if r.status == http.StatusNotFound {
		return nil, StateAbsent, nil
	}
	if r.status != http.StatusOK {
		return nil, StateError, fmt.Errorf("HTTP %d", r.status)
	}
	part, err := parsers[name](r.body)
	if err != nil {
		return nil, StateError, err
	}
	if part == nil {
		return nil, StateAbsent, nil
	}
	return part, StateOK, nil
}

type kevFeed struct {
	Version string     `json:"catalogVersion"`
	Count   int        `json:"count"`
	Vulns   []kevEntry `json:"vulnerabilities"`
}

type kevEntry struct {
	CVE        string `json:"cveID"`
	Vendor     string `json:"vendorProject"`
	Product    string `json:"product"`
	Name       string `json:"vulnerabilityName"`
	DateAdded  string `json:"dateAdded"`
	DueDate    string `json:"dueDate"`
	Action     string `json:"requiredAction"`
	Ransomware string `json:"knownRansomwareCampaignUse"`
}

func (c *Client) kevPath() string {
	if c.CacheDir == "" {
		return ""
	}
	return filepath.Join(c.CacheDir, "kev.json")
}

func (c *Client) kevBody(ctx context.Context) ([]byte, error) {
	path := c.kevPath()
	if path != "" {
		if st, err := os.Stat(path); err == nil && c.Now().Sub(st.ModTime()) < c.KEVTTL {
			if b, err := os.ReadFile(path); err == nil {
				return b, nil
			}
		}
	}
	r := c.fetch(ctx, urls[KEV])
	if r.err == nil && r.status != http.StatusOK {
		r.err = fmt.Errorf("HTTP %d", r.status)
	}
	if r.err == nil {
		var probe kevFeed
		if r.err = json.Unmarshal(r.body, &probe); r.err == nil && path != "" {
			if os.MkdirAll(filepath.Dir(path), 0o700) == nil {
				tmp := path + ".tmp"
				if os.WriteFile(tmp, r.body, 0o600) == nil {
					_ = os.Rename(tmp, path)
				}
			}
		}
	}
	if r.err != nil {
		if path != "" {
			if b, err := os.ReadFile(path); err == nil {
				return b, nil
			}
		}
		return nil, r.err
	}
	return r.body, nil
}

func (c *Client) collectKEV(ctx context.Context, cve string, f *Facts, record Record) Source {
	src := Source{Name: KEV, URL: urls[KEV]}
	body, err := c.kevBody(ctx)
	var feed kevFeed
	if err == nil {
		err = json.Unmarshal(body, &feed)
	}
	if err != nil {
		src.State, src.Error = StateError, err.Error()
		src.Evidence = record(KEV, src.URL, "", err)
		return src
	}
	part := &Facts{KEVChecked: true}
	out := fmt.Sprintf("catalogVersion %s, %d entrées : %s absente du catalogue", feed.Version, feed.Count, cve)
	for _, v := range feed.Vulns {
		if v.CVE == cve {
			part.KEV = &KEVEntry{DateAdded: v.DateAdded, DueDate: v.DueDate, Action: oneLine(v.Action), Ransomware: v.Ransomware, Name: oneLine(v.Name)}
			b, _ := json.MarshalIndent(v, "", "  ")
			out = fmt.Sprintf("catalogVersion %s, %d entrées : entrée de %s\n%s", feed.Version, feed.Count, cve, b)
			break
		}
	}
	src.State = StateOK
	src.Hash = part.hash()
	src.Evidence = record(KEV, src.URL, out, nil)
	f.merge(part)
	return src
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func digest(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}
