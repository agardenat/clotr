package dat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/tools"
)

const (
	IaC   = "iac"
	Drift = "drift"
	Clean = "clean"

	ModeDAT     = "dat"
	ModeDiagram = "diagram"

	Prefix        = "diagram"
	ReferenceTool = "diagram_reference"
	ShapesTool    = "diagram_shapes"
	RenderTool    = "diagram_render"
	TaskID        = "schema"

	DriftMark = "[ÉCART]"
	indexFile = "diagrams.json"
)

var Variants = []string{IaC, Drift, Clean}

func Valid(v string) bool { return slices.Contains(Variants, v) }

func ToolNames() []string { return []string{ReferenceTool, ShapesTool, RenderTool} }

type Rendered struct {
	Drawio   []byte
	PNG      []byte
	Warnings []string
	Notes    []string
}

type Renderer interface {
	Reference(ctx context.Context, cloud string) (string, error)
	Shapes(ctx context.Context, query, cloud string) (string, error)
	Render(ctx context.Context, cloud string, spec map[string]any) (*Rendered, error)
}

type Diagram struct {
	Name     string   `json:"name"`
	Cloud    string   `json:"cloud"`
	Title    string   `json:"title"`
	PNG      string   `json:"png,omitempty"`
	Drawio   string   `json:"drawio,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

func (d Diagram) Clean() bool { return d.PNG != "" && len(d.Warnings) == 0 }

type Unit struct {
	IaC       string
	Instances []string
	Objects   []string
	Except    []string
	Checklist []string
}

type Store struct {
	Variant     string
	DiagramOnly bool
	Renderer    Renderer
	Skipped     string
	Instances   []string
	IaCOnes     []string
	Units       []Unit
	Events      progress.Sink

	audit    *audit.Logger
	mu       sync.Mutex
	dir      string
	diagrams []Diagram
	refs     map[string]string
}

func New(variant string, diagramOnly bool, r Renderer, log *audit.Logger) *Store {
	return &Store{Variant: variant, DiagramOnly: diagramOnly, Renderer: r, Events: progress.Nop{}, audit: log, refs: map[string]string{}}
}

func (s *Store) Mode() string {
	if s.DiagramOnly {
		return ModeDiagram
	}
	return ModeDAT
}

func (s *Store) Begin(dir string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dir, s.diagrams = dir, nil
}

func (s *Store) Restore(dir string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dir, s.diagrams = dir, nil
	data, err := os.ReadFile(filepath.Join(dir, indexFile))
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &s.diagrams)
}

func (s *Store) Diagrams() []Diagram {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.diagrams)
}

func (s *Store) Rendered() bool {
	return slices.ContainsFunc(s.Diagrams(), Diagram.Clean)
}

func (s *Store) Tools() []tools.Tool {
	if s.Renderer == nil {
		return nil
	}
	return []tools.Tool{referenceTool{s}, shapesTool{s}, renderTool{s}}
}

func (s *Store) Blocks() (map[string]string, []string) {
	var b strings.Builder
	n := 0
	for _, d := range s.Diagrams() {
		if d.PNG == "" {
			continue
		}
		n++
		title := d.Title
		if title == "" {
			title = d.Name
		}
		fmt.Fprintf(&b, "![%s](%s)\n\n", i18n.R("dat.figure", n, title), d.PNG)
	}
	if n == 0 {
		msg := i18n.R("dat.no_diagram")
		if s.Skipped != "" {
			msg = s.Skipped
		}
		b.WriteString("*" + msg + "*")
	}
	return map[string]string{"diagram": strings.TrimSpace(b.String())}, []string{"diagram"}
}

var nameRe = regexp.MustCompile(`[^a-z0-9-]+`)

const mainName = "architecture"

func fileName(name string) string {
	n := strings.Trim(nameRe.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if n == "" {
		n = mainName
	}
	if !strings.HasPrefix(n, mainName) {
		n = mainName + "-" + n
	}
	return n
}

func (s *Store) record(d Diagram, r *Rendered) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == "" {
		return errors.New("répertoire du tour inconnu")
	}
	if len(r.Drawio) > 0 {
		d.Drawio = d.Name + ".drawio"
		if err := os.WriteFile(filepath.Join(s.dir, d.Drawio), r.Drawio, 0o600); err != nil {
			return err
		}
	}
	if len(r.PNG) > 0 {
		d.PNG = d.Name + ".png"
		if err := os.WriteFile(filepath.Join(s.dir, d.PNG), r.PNG, 0o600); err != nil {
			return err
		}
	}
	i := slices.IndexFunc(s.diagrams, func(x Diagram) bool { return x.Name == d.Name })
	if i < 0 && d.Name == mainName {
		s.diagrams = slices.Insert(s.diagrams, 0, d)
	} else if i < 0 {
		s.diagrams = append(s.diagrams, d)
	} else {
		s.diagrams[i] = d
	}
	data, err := json.MarshalIndent(s.diagrams, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, indexFile), data, 0o600)
}

func cloudArg(c string) (string, error) {
	c = strings.ToLower(strings.TrimSpace(c))
	if c == "" {
		return "", errors.New("cloud requis")
	}
	return c, nil
}

type referenceTool struct{ s *Store }

func (referenceTool) Name() string { return ReferenceTool }

func (referenceTool) Description() string {
	return "Référence du format de schéma pour un cloud ou une plateforme : structure de la spec (groupes, nœuds, liens), types valides, règles de placement et de disposition, exemple. À appeler avant de construire la spec de ce cloud."
}

func (referenceTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"cloud":{"type":"string","description":"cloud ou plateforme, ex: azure, aws, gcp, ovh, ocp"}},"required":["cloud"]}`)
}

func (t referenceTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	a, err := tools.Decode[struct {
		Cloud string `json:"cloud"`
	}](raw)
	if err != nil {
		return "", err
	}
	cloud, err := cloudArg(a.Cloud)
	if err != nil {
		return "", err
	}
	t.s.mu.Lock()
	ref, ok := t.s.refs[cloud]
	t.s.mu.Unlock()
	if ok {
		return ref, nil
	}
	ref, err = t.s.Renderer.Reference(ctx, cloud)
	if err != nil {
		return "", err
	}
	t.s.mu.Lock()
	t.s.refs[cloud] = ref
	t.s.mu.Unlock()
	return ref, nil
}

type shapesTool struct{ s *Store }

func (shapesTool) Name() string { return ShapesTool }

func (shapesTool) Description() string {
	return "Cherche le type à donner à un nœud du schéma pour un service (nom en langage courant, ex: load balancer, redis, kubernetes, object storage). Un type inconnu se dessine en boîte nue : cherche dès que tu n'es pas certain."
}

func (shapesTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","description":"nom du service en langage courant"},"cloud":{"type":"string","description":"cloud ou plateforme du schéma"}},"required":["query","cloud"]}`)
}

func (t shapesTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	a, err := tools.Decode[struct {
		Query string `json:"query"`
		Cloud string `json:"cloud"`
	}](raw)
	if err != nil {
		return "", err
	}
	cloud, err := cloudArg(a.Cloud)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(a.Query) == "" {
		return "", errors.New("query requis")
	}
	return t.s.Renderer.Shapes(ctx, a.Query, cloud)
}

type renderTool struct{ s *Store }

func (renderTool) Name() string { return RenderTool }

func (renderTool) Description() string {
	return "Rend un schéma d'architecture à partir de sa spec (format donné par " + ReferenceTool + ") : fichier éditable et image insérée dans le rapport. Rappelle-le avec le même name et la spec corrigée tant qu'il renvoie des avertissements."
}

func (renderTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"name":{"type":"string","description":"nom du schéma : architecture pour le premier, architecture-<plateforme> pour les suivants"},"cloud":{"type":"string","description":"cloud ou plateforme du schéma"},"title":{"type":"string","description":"titre de la figure, ex: Architecture globale du périmètre"},"spec":{"type":"object","description":"spec du schéma, au format de la référence"}},"required":["name","cloud","title","spec"]}`)
}

func (t renderTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	a, err := tools.Decode[struct {
		Name  string         `json:"name"`
		Cloud string         `json:"cloud"`
		Title string         `json:"title"`
		Spec  map[string]any `json:"spec"`
	}](raw)
	if err != nil {
		return "", err
	}
	cloud, err := cloudArg(a.Cloud)
	if err != nil {
		return "", err
	}
	if len(a.Spec) == 0 {
		return "", errors.New("spec requise")
	}
	r, err := t.s.Renderer.Render(ctx, cloud, a.Spec)
	if err != nil {
		return "", err
	}
	if len(r.PNG) == 0 && len(r.Warnings) == 0 {
		r.Warnings = []string{"aucune image produite"}
	}
	d := Diagram{Name: fileName(a.Name), Cloud: cloud, Title: strings.TrimSpace(a.Title), Warnings: r.Warnings}
	if err := t.s.record(d, r); err != nil {
		return "", err
	}
	c := tools.CallerFrom(ctx)
	t.s.audit.Log("diagram", map[string]any{"task": c.Task, "name": d.Name, "cloud": cloud, "warnings": r.Warnings, "notes": r.Notes, "png": len(r.PNG), "drawio": len(r.Drawio)})
	for _, n := range r.Notes {
		t.s.Events.Emit(progress.Event{Task: c.Task, Kind: "step", Model: c.Model, Effort: c.Effort, Detail: i18n.T("dat.diagram_note", d.Name, n)})
	}
	if len(r.Warnings) > 0 {
		t.s.Events.Emit(progress.Event{Task: c.Task, Kind: "step", Model: c.Model, Effort: c.Effort, Detail: i18n.T("dat.diagram_warnings", d.Name, len(r.Warnings))})
		return fmt.Sprintf("schéma %s rendu avec %d avertissement(s) : corrige la spec et rappelle %s avec name %q.\n- %s", d.Name, len(r.Warnings), RenderTool, d.Name, strings.Join(r.Warnings, "\n- ")), nil
	}
	t.s.Events.Emit(progress.Event{Task: c.Task, Kind: "step", Model: c.Model, Effort: c.Effort, Detail: i18n.T("dat.diagram_done", d.Name)})
	return fmt.Sprintf("schéma %s rendu sans avertissement (%s) : il sera inséré dans le rapport.", d.Name, d.PNG), nil
}
