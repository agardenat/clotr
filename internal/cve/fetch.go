package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/cve/sources"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/tools"
)

type cached struct {
	Saved    string         `json:"saved"`
	Facts    *sources.Facts `json:"facts"`
	Advisory Advisory       `json:"advisory"`
	changes  []string
}

var (
	citation = regexp.MustCompile(`\s*\[E(?:\d+\.)?\d{3,}\]`)
	safeID   = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	now      = time.Now
)

const ClotrModel = "clotr"

func (s *Store) cachePath(id string) string {
	if s.CacheDir == "" || !safeID.MatchString(id) {
		return ""
	}
	return filepath.Join(s.CacheDir, id+".json")
}

func (s *Store) load(id string) *cached {
	path := s.cachePath(id)
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var c cached
	if json.Unmarshal(b, &c) != nil || c.Facts == nil || c.Advisory.CVE != id {
		return nil
	}
	return &c
}

func strip(s string) string { return strings.TrimSpace(citation.ReplaceAllString(s, "")) }

func (s *Store) save(adv *Advisory) {
	path := s.cachePath(adv.CVE)
	if path == "" || adv.Facts == nil {
		return
	}
	narrative := *adv
	narrative.Facts, narrative.Evidence, narrative.Verified, narrative.Task, narrative.Cached, narrative.Changes = nil, nil, false, "", "", nil
	for _, p := range []*string{&narrative.Product, &narrative.Affected, &narrative.Fixed, &narrative.Summary, &narrative.Exposure, &narrative.Detection, &narrative.Mitigation, &narrative.Remediation} {
		*p = strip(*p)
	}
	for i := range narrative.IOCs {
		narrative.IOCs[i] = strip(narrative.IOCs[i])
	}
	b, err := json.MarshalIndent(cached{Saved: now().Format(time.DateOnly), Facts: adv.Facts, Advisory: narrative}, "", "  ")
	if err == nil {
		if err = os.MkdirAll(s.CacheDir, 0o700); err == nil {
			tmp := path + ".tmp"
			if err = os.WriteFile(tmp, b, 0o600); err == nil {
				err = os.Rename(tmp, path)
			}
		}
	}
	if err != nil {
		s.audit.Log("cve_cache_error", map[string]any{"cve": adv.CVE, "error": err.Error()})
		return
	}
	s.audit.Log("cve_cache_saved", map[string]any{"cve": adv.CVE, "path": path})
}

func bracket(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, "["+id+"]")
	}
	return out
}

func (s *Store) Prepare(ctx context.Context) {
	if s.Sources == nil {
		return
	}
	for _, id := range s.IDs {
		if ctx.Err() != nil {
			return
		}
		if !sources.Official(id) {
			continue
		}
		facts := s.Sources.Collect(ctx, id, func(src, url, body string, err error) string {
			args, _ := json.Marshal(map[string]string{"source": src, "url": url})
			return s.ev.Add(triageTask, sources.ToolName, string(args), body, err)
		})
		s.audit.Log("cve_sources", map[string]any{"cve": id, "sources": facts.Sources})
		s.Events.Emit(progress.Event{Task: triageTask, Kind: "cve", Status: "sources", Detail: i18n.T("cve.sources", id, sourceStates(facts))})
		s.mu.Lock()
		s.facts[id] = facts
		s.mu.Unlock()
		if !facts.Found() {
			continue
		}
		prev := s.load(id)
		if prev == nil {
			continue
		}
		if changed, diff := sources.Changed(prev.Facts, facts); changed {
			if len(diff) == 0 {
				diff = []string{i18n.R("cve.changed_sources")}
			}
			prev.changes = diff
			s.mu.Lock()
			s.prior[id] = prev
			s.mu.Unlock()
			s.audit.Log("cve_cache_changed", map[string]any{"cve": id, "saved": prev.Saved, "changes": diff})
			continue
		}
		adv := prev.Advisory
		adv.Facts, adv.Score, adv.Evidence, adv.Verified, adv.Cached, adv.Changes = facts, MainScore(facts), bracket(facts.Evidence()), true, prev.Saved, nil
		adv.Commands = slices.Clone(adv.Commands)
		for _, c := range slices.Backward(facts.Commands()) {
			if !slices.Contains(adv.Commands, c) {
				adv.Commands = slices.Insert(adv.Commands, 0, c)
			}
		}
		s.audit.Log("cve_cache_hit", map[string]any{"cve": id, "saved": prev.Saved})
		if err := s.register(tools.Caller{Task: triageTask, Model: ClotrModel}, &adv); err != nil {
			s.audit.Log("cve_cache_error", map[string]any{"cve": id, "error": err.Error()})
		}
	}
}

func sourceStates(f *sources.Facts) string {
	var parts []string
	for _, src := range f.Sources {
		mark := "✓"
		switch src.State {
		case sources.StateAbsent:
			mark = "—"
		case sources.StateError:
			mark = "✗ " + src.Error
		}
		parts = append(parts, sourceLabel(src.Name)+" "+mark)
	}
	return strings.Join(parts, " · ")
}

func sourceLabel(name string) string {
	switch name {
	case sources.CVEOrg:
		return "CVE.org"
	case sources.NVD:
		return "NVD"
	case sources.KEV:
		return "CISA KEV"
	case sources.EPSS:
		return "EPSS"
	case sources.GitHub:
		return "GitHub"
	case sources.RedHat:
		return "Red Hat"
	case sources.Ubuntu:
		return "Ubuntu"
	case sources.Debian:
		return "Debian"
	}
	return name
}

func (s *Store) NeedsWeb() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.missing() {
		if f := s.facts[id]; f == nil || !f.Found() {
			return true
		}
	}
	return false
}

func (s *Store) Brief() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for _, id := range s.missing() {
		f := s.facts[id]
		if f == nil || !f.Found() {
			states := ""
			if f != nil {
				states = " (" + sourceStates(f) + ")"
			}
			fmt.Fprintf(&b, "\n\n## %s\nInconnu des sources officielles interrogées par clotr%s : établis la fiche par recherche web (avis de l'éditeur, rapport d'incident) ; elle sera présentée comme hors sources officielles.", id, states)
			continue
		}
		fmt.Fprintf(&b, "\n\n## %s\nSources officielles interrogées par clotr, chacune enregistrée comme preuve (lis le détail avec %s si besoin) :", id, "evidence_read")
		for _, src := range f.Sources {
			fmt.Fprintf(&b, "\n- %s : %s", sourceLabel(src.Name), src.State)
			if src.Evidence != "" {
				fmt.Fprintf(&b, " [%s]", src.Evidence)
			}
			if src.Error != "" {
				b.WriteString(" (" + src.Error + ")")
			}
		}
		b.WriteString("\nFaits extraits par clotr (joints à la fiche, ne les recopie pas) :")
		line := func(label, v string) {
			if v != "" {
				fmt.Fprintf(&b, "\n- %s : %s", label, v)
			}
		}
		line("titre", f.Title)
		line("description", f.Description)
		line("CWE", strings.Join(f.CWE, ", "))
		line("scores", strings.Join(strs(f.Scores, sources.Score.String), " ; "))
		line("exploitation", exploitLine(f))
		line("versions amont", strings.Join(strs(f.Upstream, func(r sources.Range) string { return r.Product + " " + r.Versions }), " ; "))
		line("paquets applicatifs", strings.Join(strs(f.Packages, sources.Package.String), " ; "))
		line("distributions", strings.Join(strs(f.Fixes, sources.Fix.String), " ; "))
		for _, m := range f.Mitigations {
			line("contournement "+m.Source, m.Text)
		}
		for _, st := range f.Statements {
			line("note "+st.Source, st.Text)
		}
		if cmds := f.Commands(); len(cmds) > 0 {
			line("commandes de détection générées", "`"+strings.Join(cmds, "` ; `")+"`")
		}
		if p := s.prior[id]; p != nil {
			prev, _ := json.Marshal(p.Advisory)
			fmt.Fprintf(&b, "\nFiche précédente du %s, rédigée à partir des mêmes sources : reprends-la mot pour mot, et ne modifie que ce que les changements suivants imposent : %s\nFiche précédente : %s", p.Saved, strings.Join(p.changes, " ; "), prev)
		}
	}
	return b.String()
}

func strs[T any](items []T, fn func(T) string) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, fn(it))
	}
	return out
}
