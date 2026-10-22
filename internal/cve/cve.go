package cve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/memory"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/tools"
)

const (
	AdvisoryTool = "cve_advisory"
	ReportTool   = "cve_report"
	Kind         = "cve"
	Clean        = "clean"
	Vulnerable   = "vulnerable"
	Unknown      = "unknown"
)

var idRe = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)

func Extract(text string) []string {
	var out []string
	for _, m := range idRe.FindAllString(text, -1) {
		if id := strings.ToUpper(m); !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

type Advisory struct {
	CVE       string   `json:"cve"`
	Product   string   `json:"product"`
	Affected  string   `json:"affected"`
	Fixed     string   `json:"fixed"`
	Exposure  string   `json:"exposure,omitempty"`
	Detection string   `json:"detection"`
	Commands  []string `json:"commands,omitempty"`
	Evidence  []string `json:"evidence,omitempty"`
	Verified  bool     `json:"verified"`
	Task      string   `json:"task"`
}

type Finding struct {
	CVE      string   `json:"cve"`
	Asset    string   `json:"asset"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail"`
	Evidence []string `json:"evidence"`
	Task     string   `json:"task"`
	Previous string   `json:"previous,omitempty"`
}

type Store struct {
	Events     progress.Sink
	IDs        []string
	mem        *memory.Store
	ev         *evidence.Store
	audit      *audit.Logger
	mu         sync.Mutex
	advisories []*Advisory
	findings   []*Finding
	news       []news
	seen       map[string]int
	mark       map[string]int
}

const (
	ReminderEvery = 4
	InboxFormat   = "Transmis par clotr pendant que tu travailles :\n%s\nLes fiches et les statuts signalés par les autres tâches sont établis par elles : ne refais pas ces actifs."
)

var notCheck = []string{"evidence_", "memory_", "cve_", "mcp_websearch", "web_search"}

func checking(tool string) bool {
	for _, p := range notCheck {
		if strings.HasPrefix(tool, p) {
			return false
		}
	}
	return true
}

type news struct {
	task, line string
}

func New(ids []string, mem *memory.Store, ev *evidence.Store, log *audit.Logger) *Store {
	return &Store{Events: progress.Nop{}, IDs: ids, mem: mem, ev: ev, audit: log, seen: map[string]int{}, mark: map[string]int{}}
}

func (s *Store) Tools() []tools.Tool { return []tools.Tool{advisoryTool{s}, reportTool{s}} }

func ToolNames() []string { return []string{AdvisoryTool, ReportTool} }

func (s *Store) Advisories() []Advisory {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Advisory, len(s.advisories))
	for i, a := range s.advisories {
		out[i] = *a
	}
	return out
}

func (s *Store) Findings() []Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Finding, len(s.findings))
	for i, f := range s.findings {
		out[i] = *f
	}
	return out
}

func (s *Store) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, a := range s.advisories {
		out = append(out, a.Commands...)
	}
	return out
}

func (s *Store) Missing() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, id := range s.IDs {
		if !slices.ContainsFunc(s.advisories, func(a *Advisory) bool { return a.CVE == id }) {
			out = append(out, id)
		}
	}
	return out
}

func (s *Store) Inbox(reader tools.Caller) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for i := s.seen[reader.Task]; i < len(s.news); i++ {
		if s.news[i].task != reader.Task {
			b.WriteString("- " + s.news[i].line + "\n")
		}
	}
	s.seen[reader.Task] = len(s.news)
	if reader.Task != "t0" {
		if n := s.ev.TaskCount(reader.Task, checking); n-s.mark[reader.Task] >= ReminderEvery {
			fmt.Fprintf(&b, "- Rappel : %d sorties d'outils depuis ton dernier %s. Signale maintenant, un appel par actif, chaque actif dont le statut est déjà établi (clean, vulnerable ou unknown avec ce qui manque), avant toute autre vérification ; ne garde rien pour ta conclusion.\n", n-s.mark[reader.Task], ReportTool)
			s.mark[reader.Task] = n
			s.audit.Log("cve_reminder", map[string]any{"task": reader.Task, "outputs": n})
		}
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func (s *Store) checkEvidence(list tools.StringList, required bool) ([]string, error) {
	var ids []string
	for _, id := range list {
		id = strings.Trim(strings.TrimSpace(id), "[]")
		if id == "" {
			continue
		}
		if !s.ev.Has(id) {
			return nil, fmt.Errorf("preuve %s inconnue dans ce run : cite l'identifiant [Exxx] d'une sortie d'outil", id)
		}
		ids = append(ids, "["+id+"]")
	}
	if required && len(ids) == 0 {
		return nil, errors.New("au moins une preuve requise")
	}
	return ids, nil
}

func (s *Store) checkID(id string) (string, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	if !slices.Contains(s.IDs, id) {
		return "", fmt.Errorf("CVE %q hors de la demande (%s)", id, strings.Join(s.IDs, ", "))
	}
	return id, nil
}

type advisoryTool struct{ s *Store }

func (advisoryTool) Name() string { return AdvisoryTool }

func (advisoryTool) Description() string {
	return "Enregistre la fiche d'une CVE de la demande, établie depuis des sources vérifiées (avis de l'éditeur, NVD, distribution) : produit et composant, versions touchées, versions corrigées, conditions d'exposition, moyen de détection sur un actif (commande de version, paquet, fichier). commands : les commandes de détection exactes, une ligne shell chacune (ex. « php -v », « rpm -qa | grep -i php ») : elles sont réputées fiables et s'exécutent sur les actifs sans confirmation de l'utilisateur ; n'y mets que des commandes sans effet de bord. La fiche est affichée tout de suite à l'utilisateur et transmise à toutes les tâches. evidence : les preuves [Exxx] des sources (recherche web) ; sans source vérifiée, laisse evidence vide : la fiche est marquée non vérifiée. Une nouvelle fiche pour la même CVE remplace la précédente."
}

func (advisoryTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"cve":{"type":"string","description":"identifiant, ex: CVE-2026-12345"},"product":{"type":"string","description":"produit et composant touchés"},"affected":{"type":"string","description":"versions touchées, ex: PHP 8.1 < 8.1.31, 8.2 < 8.2.27"},"fixed":{"type":"string","description":"versions corrigées ou correctif"},"exposure":{"type":"string","description":"conditions d'exposition (module, configuration, accès réseau), si connues"},"detection":{"type":"string","description":"comment vérifier un actif : commande de version, nom de paquet, fichier"},"commands":{"type":"array","items":{"type":"string"},"description":"commandes de détection exactes, une ligne shell chacune, sans effet de bord"},"evidence":{"type":"array","items":{"type":"string"},"description":"preuves des sources, ex: [\"E004\"]"}},"required":["cve","product","affected","fixed","detection","commands"]}`)
}

func (t advisoryTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	a, err := tools.Decode[struct {
		CVE       string           `json:"cve"`
		Product   string           `json:"product"`
		Affected  string           `json:"affected"`
		Fixed     string           `json:"fixed"`
		Exposure  string           `json:"exposure"`
		Detection string           `json:"detection"`
		Commands  tools.StringList `json:"commands"`
		Evidence  tools.StringList `json:"evidence"`
	}](raw)
	if err != nil {
		return "", err
	}
	id, err := t.s.checkID(a.CVE)
	if err != nil {
		return "", err
	}
	for name, v := range map[string]string{"product": a.Product, "affected": a.Affected, "fixed": a.Fixed, "detection": a.Detection} {
		if strings.TrimSpace(v) == "" {
			return "", fmt.Errorf("%s requis", name)
		}
	}
	if len(a.Commands) == 0 {
		return "", fmt.Errorf("commands requis : les commandes de détection exactes, une ligne shell chacune (ex. « php -v », « rpm -qa | grep -i php »)")
	}
	ids, err := t.s.checkEvidence(a.Evidence, false)
	if err != nil {
		return "", err
	}
	var cmds []string
	for _, cmd := range a.Commands {
		if strings.ContainsAny(cmd, "\x00\n\r") {
			return "", fmt.Errorf("commande %q : une seule ligne attendue", cmd)
		}
		if cmd = oneLine(cmd); cmd != "" && !slices.Contains(cmds, cmd) {
			cmds = append(cmds, cmd)
		}
	}
	c := tools.CallerFrom(ctx)
	adv := &Advisory{CVE: id, Product: oneLine(a.Product), Affected: oneLine(a.Affected), Fixed: oneLine(a.Fixed), Exposure: oneLine(a.Exposure), Detection: oneLine(a.Detection), Commands: cmds, Evidence: ids, Verified: len(ids) > 0, Task: c.Task}
	line := adv.line()
	t.s.mu.Lock()
	t.s.advisories = slices.DeleteFunc(t.s.advisories, func(x *Advisory) bool { return x.CVE == id })
	t.s.advisories = append(t.s.advisories, adv)
	t.s.news = append(t.s.news, news{c.Task, line})
	t.s.mu.Unlock()
	if _, err := t.s.mem.Put(memory.Entry{Key: "cve/" + id + "/fiche", Content: line, Tags: []string{Kind, "fiche"}, Kind: Kind, Task: c.Task, Model: c.Model, Sovereign: c.Sovereign}); err != nil {
		return "", err
	}
	t.s.audit.Log("cve_advisory", map[string]any{"task": c.Task, "model": c.Model, "advisory": adv})
	t.s.Events.Emit(progress.Event{Task: c.Task, Kind: "cve", Model: c.Model, Detail: i18n.T("cve.advisory", line)})
	return "fiche enregistrée : affichée à l'utilisateur et transmise aux autres tâches", nil
}

func (a *Advisory) line() string {
	s := fmt.Sprintf("%s : %s ; touchées : %s ; corrigées : %s ; détection : %s", a.CVE, a.Product, a.Affected, a.Fixed, a.Detection)
	if a.Exposure != "" {
		s += " ; exposition : " + a.Exposure
	}
	if len(a.Commands) > 0 {
		s += " ; commandes de détection : `" + strings.Join(a.Commands, "` ; `") + "`"
	}
	if a.Verified {
		return s + " " + strings.Join(a.Evidence, "")
	}
	return s + " [NON VÉRIFIÉE]"
}

type reportTool struct{ s *Store }

func (reportTool) Name() string { return ReportTool }

func (reportTool) Description() string {
	return "Signale tout de suite le statut d'un actif (pod, image, workload, hôte) pour une CVE de la demande, appuyé par au moins une preuve [Exxx] : l'utilisateur le voit aussitôt et les autres tâches le reçoivent. status : vulnerable si une preuve montre une version touchée (selon la fiche de la CVE) ; clean seulement si une preuve couvre la CVE pour cet actif (composant absent de l'inventaire des paquets ou de l'image, version corrigée) ; unknown sinon (binaire introuvable dans le PATH, image non inspectée, version illisible, accès refusé), avec ce qui manque dans detail. asset : chemin stable instance/cible/namespace/objet[/conteneur] ou instance/hôte, toujours le même pour un même actif. Re-signaler un actif remplace son statut (ex. unknown puis clean après inspection de l'image). Un signalement par actif et par CVE, puis poursuis."
}

func (reportTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"cve":{"type":"string"},"asset":{"type":"string","description":"ex: k8s-prod/prod/web/web-7d9f/app ou vm-prod/web1"},"status":{"type":"string","enum":["clean","vulnerable","unknown"]},"detail":{"type":"string","description":"version ou paquet trouvé, ou ce qui manque pour conclure"},"evidence":{"type":"array","items":{"type":"string"},"description":"ex: [\"E012\"]"}},"required":["cve","asset","status","detail","evidence"]}`)
}

func (t reportTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	a, err := tools.Decode[struct {
		CVE      string           `json:"cve"`
		Asset    string           `json:"asset"`
		Status   string           `json:"status"`
		Detail   string           `json:"detail"`
		Evidence tools.StringList `json:"evidence"`
	}](raw)
	if err != nil {
		return "", err
	}
	id, err := t.s.checkID(a.CVE)
	if err != nil {
		return "", err
	}
	asset := strings.Trim(strings.Join(strings.Fields(a.Asset), ""), "/")
	if asset == "" {
		return "", errors.New("asset requis")
	}
	if a.Status != Clean && a.Status != Vulnerable && a.Status != Unknown {
		return "", fmt.Errorf("status %q invalide (clean|vulnerable|unknown)", a.Status)
	}
	detail := oneLine(a.Detail)
	if detail == "" {
		return "", errors.New("detail requis")
	}
	ids, err := t.s.checkEvidence(a.Evidence, true)
	if err != nil {
		return "", err
	}
	c := tools.CallerFrom(ctx)
	f := &Finding{CVE: id, Asset: asset, Status: a.Status, Detail: detail, Evidence: ids, Task: c.Task}
	t.s.mu.Lock()
	for i, old := range t.s.findings {
		if old.CVE == id && strings.EqualFold(old.Asset, asset) {
			if old.Status == f.Status && old.Detail == f.Detail {
				t.s.mu.Unlock()
				return fmt.Sprintf("statut déjà signalé par %s : poursuis ta tâche", old.Task), nil
			}
			f.Previous = old.Status
			t.s.findings = slices.Delete(t.s.findings, i, i+1)
			break
		}
	}
	t.s.findings = append(t.s.findings, f)
	t.s.mark[c.Task] = t.s.ev.TaskCount(c.Task, checking)
	line := f.line()
	t.s.news = append(t.s.news, news{c.Task, line})
	t.s.mu.Unlock()
	if _, err := t.s.mem.Put(memory.Entry{Key: "cve/" + id + "/" + strings.ToLower(asset), Content: line, Tags: []string{Kind, f.Status}, Kind: Kind, Task: c.Task, Model: c.Model, Sovereign: c.Sovereign}); err != nil {
		return "", err
	}
	t.s.audit.Log("cve_report", map[string]any{"task": c.Task, "model": c.Model, "finding": f})
	t.s.Events.Emit(progress.Event{Task: c.Task, Kind: "cve", Model: c.Model, Detail: f.display(), Status: f.Status})
	return "statut signalé : affiché à l'utilisateur et transmis aux autres tâches ; poursuis avec les autres actifs", nil
}

func (f *Finding) line() string {
	return fmt.Sprintf("%s %s · %s : %s %s", label(f.Status), f.CVE, f.Asset, f.Detail, strings.Join(f.Evidence, ""))
}

func (f *Finding) display() string {
	s := fmt.Sprintf("%s %s · %s : %s %s", Icon(f.Status), f.CVE, f.Asset, f.Detail, strings.Join(f.Evidence, ""))
	if f.Previous != "" && f.Previous != f.Status {
		s += i18n.T("cve.previous", Icon(f.Previous))
	}
	return s
}

func Icon(status string) string {
	switch status {
	case Clean:
		return "✅"
	case Vulnerable:
		return "🚨"
	}
	return "❓"
}

func label(status string) string {
	switch status {
	case Clean:
		return "[sain]"
	case Vulnerable:
		return "[VULNÉRABLE]"
	}
	return "[indéterminé]"
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func cell(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}

func (s *Store) Section() string {
	advs, finds := s.Advisories(), s.Findings()
	if len(advs) == 0 && len(finds) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## " + i18n.R("cve.section") + "\n\n")
	if len(advs) > 0 {
		b.WriteString("| CVE | " + i18n.R("cve.col.product") + " | " + i18n.R("cve.col.affected") + " | " + i18n.R("cve.col.fixed") + " | " + i18n.R("cve.col.sources") + " |\n|---|---|---|---|---|\n")
		for _, a := range advs {
			src := strings.Join(a.Evidence, "")
			if !a.Verified {
				src = i18n.R("cve.unverified")
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", a.CVE, cell(a.Product), cell(a.Affected), cell(a.Fixed), src)
		}
		b.WriteString("\n")
	}
	if len(finds) > 0 {
		order := map[string]int{Vulnerable: 0, Unknown: 1, Clean: 2}
		slices.SortStableFunc(finds, func(x, y Finding) int {
			if d := order[x.Status] - order[y.Status]; d != 0 {
				return d
			}
			if c := strings.Compare(x.CVE, y.CVE); c != 0 {
				return c
			}
			return strings.Compare(x.Asset, y.Asset)
		})
		counts := map[string]int{}
		for _, f := range finds {
			counts[f.Status]++
		}
		fmt.Fprintf(&b, "🚨 %d %s · ❓ %d %s · ✅ %d %s\n\n", counts[Vulnerable], i18n.R("cve.st.vulnerable"), counts[Unknown], i18n.R("cve.st.unknown"), counts[Clean], i18n.R("cve.st.clean"))
		b.WriteString("| | CVE | " + i18n.R("cve.col.asset") + " | " + i18n.R("cve.col.detail") + " | " + i18n.R("cve.col.evidence") + " |\n|---|---|---|---|---|\n")
		for _, f := range finds {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", Icon(f.Status), f.CVE, cell(f.Asset), cell(f.Detail), strings.Join(f.Evidence, ""))
		}
	}
	return strings.TrimSuffix(b.String(), "\n")
}
