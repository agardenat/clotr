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
	"github.com/agardenat/clotr/internal/cve/sources"
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
	Compromised  = "compromised"
	Unknown      = "unknown"
	KindVuln     = "vulnerability"
	KindCompr    = "compromise"
	AssetHost    = "host"
	AssetWork    = "workload"
	AssetImage   = "image"
	AssetService = "service"
	Exposed      = "exposed"
	Limited      = "limited"
	Unmeasured   = "unmeasured"
)

var (
	assetTypes = []string{AssetHost, AssetWork, AssetImage, AssetService}
	exposures  = []string{Exposed, Limited, Unmeasured}
)

var idRe = regexp.MustCompile(`(?i)\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3})\b`)

func Extract(text string) []string {
	var out []string
	for _, m := range idRe.FindAllString(text, -1) {
		id := strings.ToUpper(m)
		if strings.HasPrefix(id, "GHSA") {
			id = "GHSA" + strings.ToLower(id[4:])
		}
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

func Subjects(flag, request string) []string {
	if flag != "" && flag != "auto" {
		if ids := Extract(flag); len(ids) > 0 {
			return ids
		}
		return []string{oneLine(flag)}
	}
	return Extract(request)
}

type Advisory struct {
	CVE         string         `json:"cve"`
	Product     string         `json:"product"`
	Affected    string         `json:"affected"`
	Fixed       string         `json:"fixed"`
	Score       string         `json:"score,omitempty"`
	Summary     string         `json:"summary,omitempty"`
	Exposure    string         `json:"exposure,omitempty"`
	Host        bool           `json:"host_component,omitempty"`
	Kind        string         `json:"kind"`
	IOCs        []string       `json:"iocs,omitempty"`
	Detection   string         `json:"detection"`
	Commands    []string       `json:"commands,omitempty"`
	Mitigation  string         `json:"mitigation,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	Evidence    []string       `json:"evidence,omitempty"`
	Verified    bool           `json:"verified"`
	Task        string         `json:"task"`
	Facts       *sources.Facts `json:"facts,omitempty"`
	Cached      string         `json:"cached,omitempty"`
	Changes     []string       `json:"changes,omitempty"`
}

type Finding struct {
	CVE        string   `json:"cve"`
	Asset      string   `json:"asset"`
	Type       string   `json:"asset_type,omitempty"`
	Status     string   `json:"status"`
	Detail     string   `json:"detail"`
	OS         string   `json:"os,omitempty"`
	Exposure   string   `json:"exposure,omitempty"`
	Conditions string   `json:"conditions,omitempty"`
	Evidence   []string `json:"evidence"`
	Task       string   `json:"task"`
	Previous   string   `json:"previous,omitempty"`
	RunsOn     []string `json:"runs_on,omitempty"`
}

type Store struct {
	Events     progress.Sink
	IDs        []string
	Sources    *sources.Client
	CacheDir   string
	facts      map[string]*sources.Facts
	prior      map[string]*cached
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
	triageTask    = "t0"
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

var notSource = []string{"evidence_", "memory_", "cve_"}

func source(tool string) bool {
	for _, p := range notSource {
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
	return &Store{Events: progress.Nop{}, IDs: ids, mem: mem, ev: ev, audit: log, seen: map[string]int{}, mark: map[string]int{}, facts: map[string]*sources.Facts{}, prior: map[string]*cached{}}
}

func (s *Store) Restore(advisories []Advisory, findings []Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range advisories {
		s.advisories = slices.DeleteFunc(s.advisories, func(x *Advisory) bool { return x.CVE == a.CVE })
		s.advisories = append(s.advisories, &a)
	}
	for _, f := range findings {
		s.findings = slices.DeleteFunc(s.findings, func(x *Finding) bool {
			return x.CVE == f.CVE && strings.EqualFold(x.Asset, f.Asset)
		})
		s.findings = append(s.findings, &f)
	}
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
	return s.missing()
}

func (s *Store) missing() []string {
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
	if reader.Task == triageTask {
		if missing := s.missing(); len(missing) > 0 {
			if n := s.ev.TaskCount(triageTask, source); n-s.mark[triageTask] >= ReminderEvery {
				fmt.Fprintf(&b, "- Rappel : %d sorties de recherche sans nouvelle fiche ; sujets sans fiche : %s. Enregistre maintenant avec %s ce que les sources établissent déjà. Les versions propres à une distribution ou à une image se vérifient ensuite, une fois l'actif lu, par les tâches planifiées, qui disposent des mêmes sources.\n", n-s.mark[triageTask], strings.Join(missing, ", "), AdvisoryTool)
				s.mark[triageTask] = n
				s.audit.Log("cve_reminder", map[string]any{"task": triageTask, "outputs": n})
			}
		}
	} else {
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
	id = oneLine(id)
	for _, known := range s.IDs {
		if strings.EqualFold(known, id) {
			return known, nil
		}
	}
	return "", fmt.Errorf("sujet %q hors de la demande (%s) : reprendre l'identifiant exact", id, strings.Join(s.IDs, ", "))
}

type advisoryTool struct{ s *Store }

func (advisoryTool) Name() string { return AdvisoryTool }

func (advisoryTool) Description() string {
	return "Enregistre la fiche d'un sujet de la demande (CVE, avis GHSA, ou compromission sans CVE, désignée par son libellé exact). Quand clotr a interrogé les sources officielles (CVE.org, NVD, CISA KEV, EPSS, GitHub, distributions), il joint lui-même à la fiche les scores, l'exploitation connue, les versions par distribution et les commandes de détection des paquets : rédige le reste à partir de ces seules preuves, sans les recopier ni les contredire. kind : vulnerability pour une faille, compromise pour une compromission de chaîne d'approvisionnement ou un paquet malveillant. summary : en quoi consiste la faille (mécanisme, impact), en deux à quatre phrases. product, affected, fixed : produit et composant, versions touchées (ou malveillantes) et corrigées (ou saines), en résumé. exposure : prérequis d'exploitation (accès réseau, authentification, module ou option activés). host_component : true si le composant est fourni par l'hôte et partagé avec ses conteneurs, comme le noyau. detection : comment vérifier un actif. commands : commandes de détection supplémentaires, une ligne shell chacune, sans effet de bord, pour ce que les commandes de paquet générées par clotr ne couvrent pas (binaire ou bibliothèque hors paquet, paquet applicatif, mesure d'une condition d'exposition) ; elles s'exécutent sur les actifs sans confirmation de l'utilisateur. mitigation : contournement temporaire en attendant le correctif, tel que les éditeurs le publient, ou « aucun contournement publié ». remediation : correctif durable (version ou paquet à déployer par distribution ou écosystème, procédure). iocs : traces d'une exploitation (journaux, fichiers, processus) ou, pour une compromission, indicateurs de compromission (empreintes, fichiers déposés, domaines et IP contactés, persistance). Pas de citation [Exxx] dans les textes : cite les preuves dans evidence ; sans source vérifiée, laisse evidence vide : la fiche est marquée non vérifiée. La fiche est affichée tout de suite à l'utilisateur et transmise à toutes les tâches ; une nouvelle fiche pour le même sujet remplace la précédente."
}

func (advisoryTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"cve":{"type":"string","description":"identifiant, ex: CVE-2026-12345"},"kind":{"type":"string","enum":["vulnerability","compromise"]},"summary":{"type":"string","description":"en quoi consiste la faille : mécanisme et impact"},"product":{"type":"string","description":"produit et composant touchés"},"affected":{"type":"string","description":"versions touchées, ex: PHP 8.1 < 8.1.31, 8.2 < 8.2.27"},"fixed":{"type":"string","description":"versions corrigées ou correctif"},"score":{"type":"string","description":"sans sources officielles jointes par clotr seulement : score publié, ex: CVSS 3.1 7.8 HIGH, ou « non publié »"},"exposure":{"type":"string","description":"prérequis d'exploitation (accès réseau, authentification, module ou option activés)"},"host_component":{"type":"boolean","description":"true si le composant est fourni par l'hôte et partagé avec ses conteneurs (noyau, par exemple)"},"detection":{"type":"string","description":"comment vérifier un actif : paquet, binaire, fichier, condition d'exposition"},"commands":{"type":"array","items":{"type":"string"},"description":"commandes de détection supplémentaires, une ligne shell chacune, sans effet de bord"},"mitigation":{"type":"string","description":"contournement temporaire publié par les éditeurs, ou « aucun contournement publié »"},"remediation":{"type":"string","description":"correctif durable : version ou paquet à déployer par distribution ou écosystème, procédure"},"iocs":{"type":"array","items":{"type":"string"},"description":"traces d'exploitation ou indicateurs de compromission, un par entrée"},"evidence":{"type":"array","items":{"type":"string"},"description":"preuves des sources, ex: [\"E004\"]"}},"required":["cve","kind","product","affected","fixed","host_component","detection","remediation"]}`)
}

func (t advisoryTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	a, err := tools.Decode[struct {
		CVE         string           `json:"cve"`
		Product     string           `json:"product"`
		Affected    string           `json:"affected"`
		Fixed       string           `json:"fixed"`
		Score       string           `json:"score"`
		Summary     string           `json:"summary"`
		Exposure    string           `json:"exposure"`
		Host        *bool            `json:"host_component"`
		Detection   string           `json:"detection"`
		Commands    tools.StringList `json:"commands"`
		Mitigation  string           `json:"mitigation"`
		Remediation string           `json:"remediation"`
		Kind        string           `json:"kind"`
		IOCs        tools.StringList `json:"iocs"`
		Evidence    tools.StringList `json:"evidence"`
	}](raw)
	if err != nil {
		return "", err
	}
	id, err := t.s.checkID(a.CVE)
	if err != nil {
		return "", err
	}
	for name, v := range map[string]string{"product": a.Product, "affected": a.Affected, "fixed": a.Fixed, "detection": a.Detection, "remediation": a.Remediation} {
		if strings.TrimSpace(v) == "" {
			return "", fmt.Errorf("%s requis", name)
		}
	}
	if a.Host == nil {
		return "", errors.New("host_component requis : true si le composant est fourni par l'hôte et partagé avec ses conteneurs (noyau, par exemple), false sinon")
	}
	kind := a.Kind
	if kind == "" {
		kind = KindVuln
	}
	if kind != KindVuln && kind != KindCompr {
		return "", fmt.Errorf("kind %q invalide (vulnerability|compromise)", a.Kind)
	}
	t.s.mu.Lock()
	facts := t.s.facts[id]
	t.s.mu.Unlock()
	official := facts != nil && facts.Found()
	if kind == KindVuln {
		if strings.TrimSpace(a.Summary) == "" {
			return "", errors.New("summary requis : en quoi consiste la faille (mécanisme, impact)")
		}
		if strings.TrimSpace(a.Mitigation) == "" {
			return "", errors.New("mitigation requis : le contournement temporaire publié par les éditeurs, ou « aucun contournement publié »")
		}
		if !official && strings.TrimSpace(a.Score) == "" {
			return "", errors.New("score requis pour une faille : le score publié par la source, ex. « CVSS 3.1 7.8 HIGH », ou « non publié » si aucune source n'en donne")
		}
	}
	var cmds []string
	if official {
		cmds = facts.Commands()
	}
	for _, cmd := range a.Commands {
		if strings.ContainsAny(cmd, "\x00\n\r") {
			return "", fmt.Errorf("commande %q : une seule ligne attendue", cmd)
		}
		if cmd = oneLine(cmd); cmd != "" && !slices.Contains(cmds, cmd) {
			cmds = append(cmds, cmd)
		}
	}
	if len(cmds) == 0 {
		return "", fmt.Errorf("commands requis : les commandes de détection exactes, une ligne shell chacune (ex. « php -v », « rpm -qa | grep -i php »)")
	}
	ids, err := t.s.checkEvidence(a.Evidence, false)
	if err != nil {
		return "", err
	}
	var iocs []string
	for _, i := range a.IOCs {
		if i = oneLine(i); i != "" {
			iocs = append(iocs, i)
		}
	}
	adv := &Advisory{CVE: id, Kind: kind, Product: oneLine(a.Product), Affected: oneLine(a.Affected), Fixed: oneLine(a.Fixed), Score: oneLine(a.Score), Summary: oneLine(a.Summary), Exposure: oneLine(a.Exposure), Host: *a.Host, Detection: oneLine(a.Detection), Commands: cmds, Mitigation: oneLine(a.Mitigation), Remediation: oneLine(a.Remediation), IOCs: iocs, Evidence: ids}
	if official {
		adv.Facts = facts
		adv.Score = MainScore(facts)
		for _, e := range facts.Evidence() {
			if e = "[" + e + "]"; !slices.Contains(adv.Evidence, e) {
				adv.Evidence = append(adv.Evidence, e)
			}
		}
		t.s.mu.Lock()
		if p := t.s.prior[id]; p != nil {
			adv.Changes = p.changes
		}
		t.s.mu.Unlock()
	}
	adv.Verified = len(adv.Evidence) > 0
	if err := t.s.register(tools.CallerFrom(ctx), adv); err != nil {
		return "", err
	}
	if official {
		t.s.save(adv)
	}
	return "fiche enregistrée : affichée à l'utilisateur et transmise aux autres tâches", nil
}

func (s *Store) register(c tools.Caller, adv *Advisory) error {
	adv.Task = c.Task
	line := adv.line()
	s.mu.Lock()
	s.advisories = slices.DeleteFunc(s.advisories, func(x *Advisory) bool { return x.CVE == adv.CVE })
	s.advisories = append(s.advisories, adv)
	s.news = append(s.news, news{c.Task, line})
	if c.Task == triageTask {
		s.mark[triageTask] = s.ev.TaskCount(triageTask, source)
	}
	s.mu.Unlock()
	if _, err := s.mem.Put(memory.Entry{Key: "cve/" + adv.CVE + "/fiche", Content: line, Tags: []string{Kind, "fiche"}, Kind: Kind, Task: c.Task, Model: c.Model, Sovereign: c.Sovereign}); err != nil {
		return err
	}
	s.audit.Log("cve_advisory", map[string]any{"task": c.Task, "model": c.Model, "advisory": adv})
	s.Events.Emit(progress.Event{Task: c.Task, Kind: "cve", Status: "advisory", Model: c.Model, Effort: c.Effort, Detail: i18n.T("cve.advisory", line), Card: adv.card()})
	return nil
}

func (a *Advisory) Line() string { return a.line() }

func (a *Advisory) line() string {
	s := fmt.Sprintf("%s : %s ; touchées : %s ; corrigées : %s ; détection : %s", a.CVE, a.Product, a.Affected, a.Fixed, a.Detection)
	if a.Kind == KindCompr {
		s = fmt.Sprintf("%s (compromission) : %s ; versions malveillantes : %s ; versions saines : %s ; détection : %s", a.CVE, a.Product, a.Affected, a.Fixed, a.Detection)
	}
	if a.Summary != "" {
		s += " ; faille : " + a.Summary
	}
	if a.Score != "" {
		s += " ; score : " + a.Score
	}
	if x := exploitLine(a.Facts); x != "" {
		s += " ; exploitation : " + x
	}
	if len(a.IOCs) > 0 {
		s += " ; indicateurs : " + strings.Join(a.IOCs, " ; ")
	}
	if a.Exposure != "" {
		s += " ; exposition : " + a.Exposure
	}
	if a.Host {
		s += " ; composant de l'hôte, partagé avec ses conteneurs"
	}
	if len(a.Commands) > 0 {
		s += " ; commandes de détection : `" + strings.Join(a.Commands, "` ; `") + "`"
	}
	if a.Mitigation != "" {
		s += " ; mitigation : " + a.Mitigation
	}
	if a.Remediation != "" {
		s += " ; correctif : " + a.Remediation
	}
	if a.Verified {
		return s + " " + strings.Join(a.Evidence, "")
	}
	return s + " [NON VÉRIFIÉE]"
}

func (a *Advisory) card() *progress.Card {
	affected, fixed := i18n.T("cve.f.affected"), i18n.T("cve.f.fixed")
	if a.Kind == KindCompr {
		affected, fixed = i18n.T("cve.f.malicious"), i18n.T("cve.f.safe")
	}
	c := &progress.Card{Title: a.CVE, Score: a.Score}
	add := func(label string, code bool, lines ...string) {
		if len(lines) > 0 && lines[0] != "" {
			c.Fields = append(c.Fields, progress.CardField{Label: label, Lines: lines, Code: code})
		}
	}
	add(i18n.T("cve.f.product"), false, a.Product)
	add(i18n.T("cve.f.summary"), false, a.Summary)
	add(i18n.T("cve.f.exploitation"), false, exploitLine(a.Facts))
	add(affected, false, a.Affected)
	add(fixed, false, a.Fixed)
	add(i18n.T("cve.f.exposure"), false, a.Exposure)
	if a.Host {
		add(i18n.T("cve.f.scope"), false, i18n.T("cve.f.host"))
	}
	add(i18n.T("cve.f.iocs"), false, a.IOCs...)
	add(i18n.T("cve.f.detection"), false, a.Detection)
	add(i18n.T("cve.f.commands"), true, a.Commands...)
	add(i18n.T("cve.f.mitigation"), false, a.Mitigation)
	add(i18n.T("cve.f.remediation"), false, a.Remediation)
	src := i18n.T("cve.f.unverified")
	if a.Verified {
		src = strings.Join(a.Evidence, " ")
	}
	add(i18n.T("cve.f.sources"), false, src)
	if a.Cached != "" {
		add(i18n.T("cve.f.cache"), false, i18n.T("cve.f.cached", a.Cached))
	} else if len(a.Changes) > 0 {
		add(i18n.T("cve.f.cache"), false, a.Changes...)
	}
	return c
}

type reportTool struct{ s *Store }

func (reportTool) Name() string { return ReportTool }

func (reportTool) Description() string {
	return "Signale tout de suite le statut d'un actif pour un sujet de la demande (CVE, GHSA ou compromission, identifiant exact de la fiche), appuyé par au moins une preuve [Exxx], celle du test qui détermine le statut : l'utilisateur le voit aussitôt et les autres tâches le reçoivent. status : compromised si une preuve montre un indicateur de compromission de la fiche (fichier, empreinte, connexion, processus, persistance) ; vulnerable si une preuve montre une version touchée ou malveillante (selon la fiche) ; clean seulement si une preuve couvre la CVE pour cet actif (composant absent de l'inventaire des paquets ou de l'image, version corrigée) ; unknown sinon (binaire introuvable dans le PATH, image non inspectée, version illisible, accès refusé), avec ce qui manque dans detail. asset : chemin stable instance/cible/namespace/objet[/conteneur] ou instance/hôte, toujours le même pour un même actif. asset_type (obligatoire) : host (VM, serveur, nœud), workload (pod, conteneur, déploiement), image, service (point d'accès managé, URL). os : la distribution lue dans /etc/os-release, au format « ID VERSION_ID VERSION_CODENAME » (ex. « ubuntu 22.04 jammy », « rhel 9.4 »), quand elle est connue : clotr y associe la version corrigée de la fiche. Pour vulnerable ou compromised : exposure (exposed si les prérequis d'exploitation de la fiche sont réunis, limited si l'un manque, unmeasured s'ils n'ont pas été mesurés) et conditions (ce qui a été mesuré, ex. « port 22 publié par le load balancer public », « module non chargé »), avec leur preuve. Si la fiche indique un composant de l'hôte : asset_type host ou workload ; un workload prend le statut de ses hôtes, cités dans runs_on et signalés avant lui, même si son image ne contient pas le composant. Re-signaler un actif remplace son statut (ex. unknown puis clean après inspection de l'image). Un signalement par actif et par CVE, puis poursuis."
}

func (reportTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"cve":{"type":"string"},"asset":{"type":"string","description":"ex: k8s-prod/prod/web/web-7d9f/app ou vm-prod/web1"},"asset_type":{"type":"string","enum":["host","workload","image","service"]},"status":{"type":"string","enum":["clean","vulnerable","compromised","unknown"]},"os":{"type":"string","description":"ID VERSION_ID VERSION_CODENAME de /etc/os-release, ex: ubuntu 22.04 jammy"},"exposure":{"type":"string","enum":["exposed","limited","unmeasured"],"description":"obligatoire pour vulnerable ou compromised"},"conditions":{"type":"string","description":"prérequis d'exploitation mesurés sur cet actif ; obligatoire pour vulnerable ou compromised"},"runs_on":{"type":"array","items":{"type":"string"},"description":"pour un workload et un composant de l'hôte : les hôtes qui l'exécutent, avec leur asset signalé"},"detail":{"type":"string","description":"version ou paquet trouvé, ou ce qui manque pour conclure"},"evidence":{"type":"array","items":{"type":"string"},"description":"preuve du test déterminant d'abord, ex: [\"E012\"]"}},"required":["cve","asset","asset_type","status","detail","evidence"]}`)
}

func (t reportTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	a, err := tools.Decode[struct {
		CVE        string           `json:"cve"`
		Asset      string           `json:"asset"`
		Status     string           `json:"status"`
		Type       string           `json:"asset_type"`
		OS         string           `json:"os"`
		Exposure   string           `json:"exposure"`
		Conditions string           `json:"conditions"`
		RunsOn     tools.StringList `json:"runs_on"`
		Detail     string           `json:"detail"`
		Evidence   tools.StringList `json:"evidence"`
	}](raw)
	if err != nil {
		return "", err
	}
	id, err := t.s.checkID(a.CVE)
	if err != nil {
		return "", err
	}
	if !slices.Contains(assetTypes, a.Type) {
		return "", fmt.Errorf("asset_type %q invalide : host (VM, serveur, nœud), workload (pod, conteneur), image ou service (point d'accès managé, URL)", a.Type)
	}
	positive := a.Status == Vulnerable || a.Status == Compromised
	exposure, conditions := a.Exposure, oneLine(a.Conditions)
	if positive {
		if !slices.Contains(exposures, exposure) {
			return "", errors.New("exposure requis pour un actif vulnerable ou compromised : exposed si les prérequis d'exploitation de la fiche sont réunis, limited si l'un manque, unmeasured s'ils n'ont pas été mesurés")
		}
		if conditions == "" {
			return "", errors.New("conditions requis pour un actif vulnerable ou compromised : ce qui a été mesuré des prérequis d'exploitation (exposition réseau, option activée), ou pourquoi ce n'est pas mesurable")
		}
	} else {
		exposure, conditions = "", ""
	}
	asset := normAsset(a.Asset)
	if asset == "" {
		return "", errors.New("asset requis")
	}
	if a.Status != Clean && a.Status != Vulnerable && a.Status != Compromised && a.Status != Unknown {
		return "", fmt.Errorf("status %q invalide (clean|vulnerable|compromised|unknown)", a.Status)
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
	f := &Finding{CVE: id, Asset: asset, Type: a.Type, Status: a.Status, Detail: detail, OS: oneLine(a.OS), Exposure: exposure, Conditions: conditions, Evidence: ids, Task: c.Task}
	t.s.mu.Lock()
	if f.RunsOn, err = t.s.checkHost(id, a.Status, a.Type, a.RunsOn); err != nil {
		t.s.mu.Unlock()
		return "", err
	}
	for i, old := range t.s.findings {
		if old.CVE == id && strings.EqualFold(old.Asset, asset) {
			if old.Status == f.Status && old.Detail == f.Detail && old.Exposure == f.Exposure && old.Conditions == f.Conditions && old.OS == f.OS {
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
	t.s.Events.Emit(progress.Event{Task: c.Task, Kind: "cve", Model: c.Model, Effort: c.Effort, Detail: f.display(), Status: f.Status})
	return "statut signalé : affiché à l'utilisateur et transmis aux autres tâches ; poursuis avec les autres actifs", nil
}

func normAsset(s string) string {
	return strings.Trim(strings.Join(strings.Fields(s), ""), "/")
}

func (s *Store) checkHost(id, status, kind string, runsOn []string) ([]string, error) {
	i := slices.IndexFunc(s.advisories, func(a *Advisory) bool { return a.CVE == id })
	if i < 0 || !s.advisories[i].Host {
		return nil, nil
	}
	if kind != AssetHost && kind != AssetWork {
		return nil, errors.New("asset_type host ou workload : la fiche indique un composant de l'hôte, qui n'est jamais dans une image ; signale l'hôte, ou le workload qui s'exécute dessus")
	}
	if kind == AssetHost {
		return nil, nil
	}
	var hosts, missing []string
	want := Clean
	for _, h := range runsOn {
		h = normAsset(h)
		if h == "" || slices.Contains(hosts, h) {
			continue
		}
		hosts = append(hosts, h)
		j := slices.IndexFunc(s.findings, func(f *Finding) bool { return f.CVE == id && strings.EqualFold(f.Asset, h) })
		switch {
		case j < 0:
			missing = append(missing, h)
		case s.findings[j].Status == Vulnerable || s.findings[j].Status == Compromised:
			want = Vulnerable
		case s.findings[j].Status == Unknown && want == Clean:
			want = Unknown
		}
	}
	if status == Unknown || status == Compromised {
		return hosts, nil
	}
	if len(hosts) == 0 {
		return nil, errors.New("runs_on requis : un workload prend le statut des hôtes qui l'exécutent, car le composant n'est pas dans son image")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("hôtes non signalés : %s ; signale-les d'abord avec le même asset (asset_type host)", strings.Join(missing, ", "))
	}
	if status != want {
		return nil, fmt.Errorf("statut %s incohérent : d'après les hôtes de runs_on, ce workload est %s", status, want)
	}
	return hosts, nil
}

func (f *Finding) withHosts() string {
	if len(f.RunsOn) == 0 {
		return f.Detail
	}
	hosts := f.RunsOn
	more := ""
	if len(hosts) > maxHosts {
		more = fmt.Sprintf(" +%d", len(hosts)-maxHosts)
		hosts = hosts[:maxHosts]
	}
	return i18n.R("cve.runs_on") + " " + strings.Join(hosts, ", ") + more + " : " + f.Detail
}

func (f *Finding) line() string {
	s := fmt.Sprintf("%s %s · %s : %s", label(f.Status), f.CVE, f.Asset, f.withHosts())
	if f.Exposure != "" {
		s += " ; exposition " + f.Exposure + " : " + f.Conditions
	}
	return s + " " + strings.Join(f.Evidence, "")
}

func (f *Finding) display() string {
	s := fmt.Sprintf("%s %s · %s : %s %s", Icon(f.Status), f.CVE, f.Asset, f.withHosts(), strings.Join(f.Evidence, ""))
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
	case Compromised:
		return "☠️"
	}
	return "❓"
}

func label(status string) string {
	switch status {
	case Clean:
		return "[sain]"
	case Vulnerable:
		return "[VULNÉRABLE]"
	case Compromised:
		return "[COMPROMIS]"
	}
	return "[indéterminé]"
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func cell(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}

const (
	maxDetail = 240
	maxHosts  = 3
)

func shorten(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func splitAsset(asset string) (group, leaf string) {
	parts := strings.Split(asset, "/")
	n := len(parts) - 1
	if len(parts) >= 4 {
		n = 3
	}
	if n <= 0 {
		return "", asset
	}
	return strings.Join(parts[:n], "/"), strings.Join(parts[n:], "/")
}
