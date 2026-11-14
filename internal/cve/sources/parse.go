package sources

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var parsers = map[string]func([]byte) (*Facts, error){
	CVEOrg: parseCVEOrg,
	NVD:    parseNVD,
	EPSS:   parseEPSS,
	GitHub: parseGitHub,
	RedHat: parseRedHat,
	Ubuntu: parseUbuntu,
	Debian: parseDebian,
}

var cweRe = regexp.MustCompile(`CWE-\d+`)

type cvssMetric struct {
	Version  string  `json:"version"`
	Score    float64 `json:"baseScore"`
	Severity string  `json:"baseSeverity"`
	Vector   string  `json:"vectorString"`
}

func (m *cvssMetric) score(source string) (Score, bool) {
	if m == nil || m.Vector == "" {
		return Score{}, false
	}
	v := m.Version
	if v == "" {
		v = vectorVersion(m.Vector)
	}
	sev := strings.ToUpper(m.Severity)
	if sev == "" {
		sev = Severity(m.Score)
	}
	return Score{Source: source, Version: v, Score: m.Score, Severity: sev, Vector: m.Vector}, true
}

func vectorVersion(vector string) string {
	if strings.HasPrefix(vector, "CVSS:") {
		v, _, _ := strings.Cut(strings.TrimPrefix(vector, "CVSS:"), "/")
		return v
	}
	return "2.0"
}

func Severity(score float64) string {
	switch {
	case score == 0:
		return "NONE"
	case score < 4:
		return "LOW"
	case score < 7:
		return "MEDIUM"
	case score < 9:
		return "HIGH"
	}
	return "CRITICAL"
}

type langText struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

func english(list []langText) string {
	for _, d := range list {
		if strings.HasPrefix(d.Lang, "en") {
			return oneLine(d.Value)
		}
	}
	if len(list) > 0 {
		return oneLine(list[0].Value)
	}
	return ""
}

func parseCVEOrg(body []byte) (*Facts, error) {
	var r struct {
		Meta struct {
			ID        string `json:"cveId"`
			State     string `json:"state"`
			Assigner  string `json:"assignerShortName"`
			Published string `json:"datePublished"`
		} `json:"cveMetadata"`
		Containers struct {
			CNA struct {
				Title        string     `json:"title"`
				Descriptions []langText `json:"descriptions"`
				Rejected     []langText `json:"rejectedReasons"`
				Metrics      []struct {
					V40 *cvssMetric `json:"cvssV4_0"`
					V31 *cvssMetric `json:"cvssV3_1"`
					V30 *cvssMetric `json:"cvssV3_0"`
				} `json:"metrics"`
				ProblemTypes []struct {
					Descriptions []struct {
						CWE         string `json:"cweId"`
						Description string `json:"description"`
					} `json:"descriptions"`
				} `json:"problemTypes"`
				Affected []struct {
					Vendor   string `json:"vendor"`
					Product  string `json:"product"`
					Package  string `json:"packageName"`
					Versions []struct {
						Version  string `json:"version"`
						Status   string `json:"status"`
						Type     string `json:"versionType"`
						LessThan string `json:"lessThan"`
						LessEq   string `json:"lessThanOrEqual"`
					} `json:"versions"`
				} `json:"affected"`
				Workarounds []langText `json:"workarounds"`
			} `json:"cna"`
			ADP []struct {
				Title   string `json:"title"`
				Metrics []struct {
					V31   *cvssMetric `json:"cvssV3_1"`
					Other struct {
						Type    string `json:"type"`
						Content struct {
							Options []map[string]string `json:"options"`
						} `json:"content"`
					} `json:"other"`
				} `json:"metrics"`
			} `json:"adp"`
		} `json:"containers"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	cna := r.Containers.CNA
	f := &Facts{Title: oneLine(cna.Title), Description: english(cna.Descriptions), Published: dateOnly(r.Meta.Published)}
	if strings.EqualFold(r.Meta.State, "REJECTED") {
		f.Title = "REJECTED"
		f.Description = english(cna.Rejected)
	}
	src := "CNA"
	if r.Meta.Assigner != "" {
		src += " " + r.Meta.Assigner
	}
	for _, m := range cna.Metrics {
		for _, c := range []*cvssMetric{m.V40, m.V31, m.V30} {
			if s, ok := c.score(src); ok {
				f.Scores = append(f.Scores, s)
			}
		}
	}
	for _, p := range cna.ProblemTypes {
		for _, d := range p.Descriptions {
			if d.CWE != "" {
				f.CWE = addUniq(f.CWE, d.CWE)
			} else {
				f.CWE = addUniq(f.CWE, cweRe.FindAllString(d.Description, -1)...)
			}
		}
	}
	for _, a := range cna.Affected {
		var ranges []string
		for _, v := range a.Versions {
			if v.Status != "affected" || v.Type == "rpm" {
				continue
			}
			r := v.Version
			switch {
			case v.LessThan != "" && v.LessThan != "*":
				r = ">= " + v.Version + ", < " + v.LessThan
			case v.LessEq != "" && v.LessEq != "*":
				r = ">= " + v.Version + ", <= " + v.LessEq
			}
			ranges = addUniq(ranges, oneLine(r))
		}
		if len(ranges) == 0 {
			continue
		}
		product := strings.TrimSpace(strings.Join(strings.Fields(a.Vendor+" "+a.Product), " "))
		if product == "" || a.Product == "" {
			product = strings.TrimSpace(a.Vendor + " " + a.Package)
		}
		f.Upstream = addUniq(f.Upstream, Range{Product: oneLine(product), Versions: strings.Join(ranges, " ; ")})
	}
	if w := english(cna.Workarounds); w != "" {
		f.Mitigations = append(f.Mitigations, Text{Source: src, Text: w})
	}
	for _, adp := range r.Containers.ADP {
		for _, m := range adp.Metrics {
			if s, ok := m.V31.score("CISA ADP"); ok {
				f.Scores = append(f.Scores, s)
			}
			for _, o := range m.Other.Content.Options {
				if v, ok := o["Exploitation"]; ok {
					f.SSVC = strings.ToLower(v)
				}
			}
		}
	}
	return f, nil
}

func dateOnly(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

func parseNVD(body []byte) (*Facts, error) {
	type metric struct {
		Source string     `json:"source"`
		Type   string     `json:"type"`
		Data   cvssMetric `json:"cvssData"`
	}
	var r struct {
		Total int `json:"totalResults"`
		Vulns []struct {
			CVE struct {
				Published    string     `json:"published"`
				Status       string     `json:"vulnStatus"`
				Descriptions []langText `json:"descriptions"`
				Metrics      struct {
					V40 []metric `json:"cvssMetricV40"`
					V31 []metric `json:"cvssMetricV31"`
					V30 []metric `json:"cvssMetricV30"`
				} `json:"metrics"`
				Weaknesses []struct {
					Type        string     `json:"type"`
					Description []langText `json:"description"`
				} `json:"weaknesses"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	if r.Total == 0 || len(r.Vulns) == 0 {
		return nil, nil
	}
	c := r.Vulns[0].CVE
	f := &Facts{Description: english(c.Descriptions), Published: dateOnly(c.Published)}
	for _, list := range [][]metric{c.Metrics.V40, c.Metrics.V31, c.Metrics.V30} {
		for _, m := range list {
			if m.Type != "Primary" {
				continue
			}
			if s, ok := m.Data.score("NVD"); ok {
				f.Scores = append(f.Scores, s)
			}
		}
	}
	for _, w := range c.Weaknesses {
		if w.Type != "Primary" {
			continue
		}
		for _, d := range w.Description {
			f.CWE = addUniq(f.CWE, cweRe.FindAllString(d.Value, -1)...)
		}
	}
	return f, nil
}

func parseEPSS(body []byte) (*Facts, error) {
	var r struct {
		Data []struct {
			EPSS       string `json:"epss"`
			Percentile string `json:"percentile"`
			Date       string `json:"date"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	if len(r.Data) == 0 {
		return nil, nil
	}
	d := r.Data[0]
	score, err := strconv.ParseFloat(d.EPSS, 64)
	if err != nil {
		return nil, fmt.Errorf("epss %q: %w", d.EPSS, err)
	}
	pct, err := strconv.ParseFloat(d.Percentile, 64)
	if err != nil {
		return nil, fmt.Errorf("percentile %q: %w", d.Percentile, err)
	}
	return &Facts{EPSS: &EPSSData{Score: score, Percentile: pct, Date: d.Date}}, nil
}

type ghAdvisory struct {
	GHSA      string  `json:"ghsa_id"`
	CVE       *string `json:"cve_id"`
	Summary   string  `json:"summary"`
	Severity  string  `json:"severity"`
	Type      string  `json:"type"`
	Withdrawn *string `json:"withdrawn_at"`
	CVSS      struct {
		V3 struct {
			Vector *string `json:"vector_string"`
			Score  float64 `json:"score"`
		} `json:"cvss_v3"`
		V4 struct {
			Vector *string `json:"vector_string"`
			Score  float64 `json:"score"`
		} `json:"cvss_v4"`
	} `json:"cvss_severities"`
	CWEs []struct {
		ID string `json:"cwe_id"`
	} `json:"cwes"`
	Vulns []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Range   string          `json:"vulnerable_version_range"`
		Patched json.RawMessage `json:"first_patched_version"`
	} `json:"vulnerabilities"`
}

func patched(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var o struct {
		ID string `json:"identifier"`
	}
	if json.Unmarshal(raw, &o) == nil {
		return o.ID
	}
	return ""
}

func parseGitHub(body []byte) (*Facts, error) {
	var list []ghAdvisory
	if t := bytes.TrimSpace(body); len(t) > 0 && t[0] == '{' {
		var one ghAdvisory
		if err := json.Unmarshal(t, &one); err != nil {
			return nil, err
		}
		list = append(list, one)
	} else if err := json.Unmarshal(body, &list); err != nil {
		return nil, err
	}
	var f *Facts
	for _, a := range list {
		if a.Withdrawn != nil {
			continue
		}
		if f == nil {
			f = &Facts{Title: oneLine(a.Summary)}
		}
		if a.CVE != nil {
			f.CVE = *a.CVE
		}
		if a.Type == "reviewed" && a.Severity != "" {
			f.Ratings = addUniq(f.Ratings, Rating{Source: "GitHub " + a.GHSA, Value: a.Severity})
		}
		for _, v := range []struct {
			vec   *string
			score float64
		}{{a.CVSS.V4.Vector, a.CVSS.V4.Score}, {a.CVSS.V3.Vector, a.CVSS.V3.Score}} {
			if v.vec == nil || *v.vec == "" {
				continue
			}
			f.Scores = addUniq(f.Scores, Score{Source: "GitHub", Version: vectorVersion(*v.vec), Score: v.score, Severity: Severity(v.score), Vector: *v.vec})
		}
		for _, c := range a.CWEs {
			f.CWE = addUniq(f.CWE, c.ID)
		}
		for _, v := range a.Vulns {
			f.Packages = addUniq(f.Packages, Package{Ecosystem: v.Package.Ecosystem, Name: v.Package.Name, Vulnerable: oneLine(v.Range), Fixed: patched(v.Patched)})
		}
	}
	return f, nil
}

func textValue(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return oneLine(s)
	}
	var o struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(raw, &o) == nil {
		return oneLine(o.Value)
	}
	return ""
}

var redhatStates = map[string]string{
	"not affected":         FixNotAffected,
	"will not fix":         FixWontFix,
	"affected":             FixAffected,
	"out of support scope": FixOutOfScope,
	"fix deferred":         FixPending,
	"under investigation":  FixPending,
	"new":                  FixPending,
}

func parseRedHat(body []byte) (*Facts, error) {
	var r struct {
		Severity  string            `json:"threat_severity"`
		Published string            `json:"public_date"`
		Details   []string          `json:"details"`
		Statement json.RawMessage   `json:"statement"`
		Mitigate  json.RawMessage   `json:"mitigation"`
		CWE       string            `json:"cwe"`
		CVSS3     map[string]string `json:"cvss3"`
		Releases  []struct {
			Product  string `json:"product_name"`
			Advisory string `json:"advisory"`
			Package  string `json:"package"`
		} `json:"affected_release"`
		States []struct {
			Product string `json:"product_name"`
			State   string `json:"fix_state"`
			Package string `json:"package_name"`
		} `json:"package_state"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	f := &Facts{Published: dateOnly(r.Published), CWE: cweRe.FindAllString(r.CWE, -1)}
	if len(r.Details) > 0 {
		f.Description = oneLine(r.Details[0])
	}
	if r.Severity != "" {
		f.Ratings = append(f.Ratings, Rating{Source: "Red Hat", Value: r.Severity})
	}
	if vec := r.CVSS3["cvss3_scoring_vector"]; vec != "" {
		score, _ := strconv.ParseFloat(r.CVSS3["cvss3_base_score"], 64)
		f.Scores = append(f.Scores, Score{Source: "Red Hat", Version: vectorVersion(vec), Score: score, Severity: Severity(score), Vector: vec})
	}
	if s := textValue(r.Statement); s != "" {
		f.Statements = append(f.Statements, Text{Source: "Red Hat", Text: s})
	}
	if s := textValue(r.Mitigate); s != "" {
		f.Mitigations = append(f.Mitigations, Text{Source: "Red Hat", Text: s})
	}
	for _, rel := range r.Releases {
		x := Fix{Distro: RedHat, Release: oneLine(rel.Product), Package: rel.Package, State: FixFixed, Advisory: rel.Advisory}
		if name, version, ok := SplitNEVR(rel.Package); ok {
			x.Package, x.Version = name, version
		}
		f.Fixes = addUniq(f.Fixes, x)
	}
	for _, st := range r.States {
		state, ok := redhatStates[strings.ToLower(st.State)]
		if !ok {
			state = strings.ToLower(st.State)
		}
		f.Fixes = addUniq(f.Fixes, Fix{Distro: RedHat, Release: oneLine(st.Product), Package: st.Package, State: state})
	}
	return f, nil
}

var ubuntuStates = map[string]string{
	"released":     FixFixed,
	"not-affected": FixNotAffected,
	"needed":       FixAffected,
	"needs-triage": FixPending,
	"pending":      FixPending,
	"deferred":     FixPending,
	"ignored":      FixIgnored,
}

func parseUbuntu(body []byte) (*Facts, error) {
	var r struct {
		Priority   string `json:"priority"`
		Mitigation string `json:"mitigation"`
		Published  string `json:"published"`
		Notes      []struct {
			Author string `json:"author"`
			Note   string `json:"note"`
		} `json:"notes"`
		Notices []struct {
			ID       string `json:"id"`
			Packages map[string][]struct {
				Name     string `json:"name"`
				IsSource bool   `json:"is_source"`
			} `json:"release_packages"`
		} `json:"notices"`
		Packages []struct {
			Name     string `json:"name"`
			Statuses []struct {
				Release     string `json:"release_codename"`
				Status      string `json:"status"`
				Description string `json:"description"`
			} `json:"statuses"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	f := &Facts{Published: dateOnly(r.Published)}
	if r.Priority != "" {
		f.Ratings = append(f.Ratings, Rating{Source: "Ubuntu", Value: r.Priority})
	}
	if m := oneLine(r.Mitigation); m != "" {
		f.Mitigations = append(f.Mitigations, Text{Source: "Ubuntu", Text: m})
	}
	for _, n := range r.Notes {
		if t := oneLine(n.Note); t != "" {
			f.Statements = append(f.Statements, Text{Source: "Ubuntu", Text: t})
		}
	}
	usn := func(release, pkg string) string {
		var ids []string
		for _, n := range r.Notices {
			for _, p := range n.Packages[release] {
				if p.IsSource && p.Name == pkg {
					ids = addUniq(ids, n.ID)
				}
			}
		}
		return strings.Join(ids, ", ")
	}
	for _, p := range r.Packages {
		for _, s := range p.Statuses {
			if s.Release == "upstream" || s.Status == "DNE" {
				continue
			}
			state, ok := ubuntuStates[s.Status]
			if !ok {
				state = s.Status
			}
			x := Fix{Distro: Ubuntu, Release: s.Release, Package: p.Name, State: state}
			if state == FixFixed {
				x.Version, x.Advisory = oneLine(s.Description), usn(s.Release, p.Name)
			} else {
				x.Note = oneLine(s.Description)
			}
			f.Fixes = append(f.Fixes, x)
		}
	}
	return f, nil
}

func parseDebian(body []byte) (*Facts, error) {
	var r struct {
		Affected []struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Ranges []struct {
				Events []map[string]string `json:"events"`
			} `json:"ranges"`
			Specific struct {
				Urgency string `json:"urgency"`
			} `json:"ecosystem_specific"`
		} `json:"affected"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	f := &Facts{}
	for _, a := range r.Affected {
		x := Fix{Distro: Debian, Release: strings.Replace(a.Package.Ecosystem, ":", " ", 1), Package: a.Package.Name, State: FixAffected}
		for _, rg := range a.Ranges {
			for _, e := range rg.Events {
				if v := e["fixed"]; v != "" {
					x.State, x.Version = FixFixed, v
				}
			}
		}
		if u := a.Specific.Urgency; u != "" && u != "not yet assigned" {
			x.Note = u
		}
		f.Fixes = addUniq(f.Fixes, x)
	}
	return f, nil
}
