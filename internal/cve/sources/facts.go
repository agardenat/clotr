package sources

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

type Facts struct {
	ID          string    `json:"id"`
	CVE         string    `json:"cve,omitempty"`
	Title       string    `json:"title,omitempty"`
	Description string    `json:"description,omitempty"`
	Published   string    `json:"published,omitempty"`
	CWE         []string  `json:"cwe,omitempty"`
	Scores      []Score   `json:"scores,omitempty"`
	Ratings     []Rating  `json:"ratings,omitempty"`
	KEVChecked  bool      `json:"kev_checked,omitempty"`
	KEV         *KEVEntry `json:"kev,omitempty"`
	EPSS        *EPSSData `json:"epss,omitempty"`
	SSVC        string    `json:"ssvc_exploitation,omitempty"`
	Upstream    []Range   `json:"upstream,omitempty"`
	Packages    []Package `json:"packages,omitempty"`
	Fixes       []Fix     `json:"fixes,omitempty"`
	Mitigations []Text    `json:"mitigations,omitempty"`
	Statements  []Text    `json:"statements,omitempty"`
	Sources     []Source  `json:"sources,omitempty"`
}

type Score struct {
	Source   string  `json:"source"`
	Version  string  `json:"version"`
	Score    float64 `json:"score"`
	Severity string  `json:"severity,omitempty"`
	Vector   string  `json:"vector,omitempty"`
}

type Rating struct {
	Source string `json:"source"`
	Value  string `json:"value"`
}

type KEVEntry struct {
	DateAdded  string `json:"date_added"`
	DueDate    string `json:"due_date,omitempty"`
	Action     string `json:"required_action,omitempty"`
	Ransomware string `json:"ransomware,omitempty"`
	Name       string `json:"name,omitempty"`
}

type EPSSData struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

type Range struct {
	Product  string `json:"product"`
	Versions string `json:"versions"`
}

type Package struct {
	Ecosystem  string `json:"ecosystem"`
	Name       string `json:"name"`
	Vulnerable string `json:"vulnerable,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type Fix struct {
	Distro   string `json:"distro"`
	Release  string `json:"release"`
	Package  string `json:"package"`
	Version  string `json:"version,omitempty"`
	State    string `json:"state"`
	Advisory string `json:"advisory,omitempty"`
	Note     string `json:"note,omitempty"`
}

type Text struct {
	Source string `json:"source"`
	Text   string `json:"text"`
}

type Source struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	State    string `json:"state"`
	Error    string `json:"error,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	Hash     string `json:"hash,omitempty"`
}

const (
	FixFixed       = "fixed"
	FixAffected    = "affected"
	FixNotAffected = "not-affected"
	FixWontFix     = "wont-fix"
	FixOutOfScope  = "out-of-support"
	FixPending     = "pending"
	FixIgnored     = "ignored"
)

func (f *Facts) has(name string) bool {
	return slices.ContainsFunc(f.Sources, func(s Source) bool { return s.Name == name })
}

func (f *Facts) Found() bool {
	return slices.ContainsFunc(f.Sources, func(s Source) bool { return s.State == StateOK && s.Name != KEV && s.Name != EPSS })
}

func (f *Facts) Evidence() []string {
	var out []string
	for _, s := range f.Sources {
		if s.State == StateOK && s.Evidence != "" {
			out = append(out, s.Evidence)
		}
	}
	return out
}

func (f *Facts) SourceOf(name string) (Source, bool) {
	for _, s := range f.Sources {
		if s.Name == name {
			return s, true
		}
	}
	return Source{}, false
}

func (f *Facts) hash() string {
	c := *f
	c.Sources, c.EPSS, c.ID, c.Published = nil, nil, "", ""
	return digest(c)
}

func addUniq[T comparable](dst []T, items ...T) []T {
	for _, it := range items {
		if !slices.Contains(dst, it) {
			dst = append(dst, it)
		}
	}
	return dst
}

const SourceSep = " · "

func addText(dst, items []Text) []Text {
	for _, it := range items {
		i := slices.IndexFunc(dst, func(t Text) bool { return t.Text == it.Text })
		switch {
		case i < 0:
			dst = append(dst, it)
		case !slices.Contains(strings.Split(dst[i].Source, SourceSep), it.Source):
			dst[i].Source += SourceSep + it.Source
		}
	}
	return dst
}

func (f *Facts) merge(p *Facts) {
	if f.CVE == "" && p.CVE != "" && p.CVE != f.ID {
		f.CVE = p.CVE
	}
	if f.Title == "" {
		f.Title = p.Title
	}
	if f.Description == "" {
		f.Description = p.Description
	}
	if f.Published == "" {
		f.Published = p.Published
	}
	f.CWE = addUniq(f.CWE, p.CWE...)
	f.Scores = addUniq(f.Scores, p.Scores...)
	f.Ratings = addUniq(f.Ratings, p.Ratings...)
	f.KEVChecked = f.KEVChecked || p.KEVChecked
	if p.KEV != nil {
		f.KEV = p.KEV
	}
	if p.EPSS != nil {
		f.EPSS = p.EPSS
	}
	if p.SSVC != "" {
		f.SSVC = p.SSVC
	}
	f.Upstream = addUniq(f.Upstream, p.Upstream...)
	f.Packages = addUniq(f.Packages, p.Packages...)
	f.Fixes = addUniq(f.Fixes, p.Fixes...)
	f.Mitigations = addText(f.Mitigations, p.Mitigations)
	f.Statements = addText(f.Statements, p.Statements)
}

func Changed(old, cur *Facts) (bool, []string) {
	if old == nil {
		return true, nil
	}
	changed := false
	for _, s := range cur.Sources {
		if s.State == StateError || s.Name == EPSS {
			continue
		}
		prev, ok := old.SourceOf(s.Name)
		if !ok || prev.State == StateError {
			if s.State == StateOK {
				changed = true
			}
			continue
		}
		if prev.State != s.State || prev.Hash != s.Hash {
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	return true, Diff(old, cur)
}

func Diff(old, cur *Facts) []string {
	var out []string
	cmp := func(label string, a, b []string) {
		for _, x := range b {
			if !slices.Contains(a, x) {
				out = append(out, "+ "+label+" : "+x)
			}
		}
		for _, x := range a {
			if !slices.Contains(b, x) {
				out = append(out, "- "+label+" : "+x)
			}
		}
	}
	cmp("CVSS", strs(old.Scores, Score.String), strs(cur.Scores, Score.String))
	cmp("sévérité", strs(old.Ratings, func(r Rating) string { return r.Source + " " + r.Value }), strs(cur.Ratings, func(r Rating) string { return r.Source + " " + r.Value }))
	cmp("KEV", kevLine(old), kevLine(cur))
	cmp("SSVC", one(old.SSVC), one(cur.SSVC))
	cmp("paquet", strs(old.Packages, Package.String), strs(cur.Packages, Package.String))
	cmp("distribution", strs(old.Fixes, Fix.String), strs(cur.Fixes, Fix.String))
	cmp("mitigation", strs(old.Mitigations, func(t Text) string { return t.Source }), strs(cur.Mitigations, func(t Text) string { return t.Source }))
	return out
}

func one(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func kevLine(f *Facts) []string {
	if f.KEV == nil {
		return nil
	}
	return []string{"ajoutée le " + f.KEV.DateAdded}
}

func strs[T any](items []T, fn func(T) string) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, fn(it))
	}
	return out
}

func (s Score) String() string {
	return fmt.Sprintf("%s CVSS %s %.1f %s", s.Source, s.Version, s.Score, s.Severity)
}

func (p Package) String() string {
	s := p.Ecosystem + " " + p.Name
	if p.Vulnerable != "" {
		s += " " + p.Vulnerable
	}
	if p.Fixed != "" {
		s += " → " + p.Fixed
	}
	return s
}

func (x Fix) String() string {
	s := x.Release + " " + x.Package + " " + x.State
	if x.Version != "" {
		s += " " + x.Version
	}
	if x.Advisory != "" {
		s += " (" + x.Advisory + ")"
	}
	return s
}

var nevra = regexp.MustCompile(`^(.+)-(\d+:[^-]+-[^-]+)$`)

func SplitNEVR(s string) (name, version string, ok bool) {
	m := nevra.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

var pkgName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]*$`)

func (f *Facts) SourcePackages(family string) []string {
	var out []string
	for _, x := range f.Fixes {
		if !pkgName.MatchString(x.Package) {
			continue
		}
		switch {
		case family == "rpm" && x.Distro == RedHat, family == "deb" && (x.Distro == Ubuntu || x.Distro == Debian):
			out = addUniq(out, x.Package)
		}
	}
	slices.Sort(out)
	return out
}

func alternation(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = regexp.QuoteMeta(n)
	}
	if len(q) == 1 {
		return q[0]
	}
	return "(" + strings.Join(q, "|") + ")"
}

const OSRelease = "cat /etc/os-release"

func (f *Facts) Commands() []string {
	rpm, deb := f.SourcePackages("rpm"), f.SourcePackages("deb")
	if len(rpm) == 0 && len(deb) == 0 {
		return nil
	}
	out := []string{OSRelease}
	if len(rpm) > 0 {
		out = append(out, fmt.Sprintf(`rpm -qa --qf '%%{NAME} %%{EPOCHNUM}:%%{VERSION}-%%{RELEASE} %%{SOURCERPM}\n' | grep -E ' %s-[0-9]'`, alternation(rpm)))
	}
	if len(deb) > 0 {
		out = append(out, fmt.Sprintf(`dpkg-query -W -f '${Package} ${Version} ${source:Package}\n' | grep -E ' %s$'`, alternation(deb)))
	}
	return out
}
