package export

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/agardenat/clotr/internal/agent"
	"github.com/agardenat/clotr/internal/catalog"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/tools"
)

const (
	TaskID   = "export"
	MaxBytes = 100 << 20
	shown    = 15
)

type Server interface {
	Name() string
	Tools() []tools.Tool
	Fetch(ctx context.Context, url string, maxBytes int64) ([]byte, error)
}

type Result struct {
	Data []byte
	Report
}

type Job struct {
	Server   Server
	Format   string
	Markdown string
	Title    string

	ctx     context.Context
	mu      sync.Mutex
	calls   [][]string
	fetched string
	result  *Result
	err     error
}

func (j *Job) Registry(maxChars int) *tools.Registry {
	reg := tools.NewRegistry(maxChars)
	for _, t := range j.Server.Tools() {
		reg.Add(&recorder{Tool: t, job: j})
	}
	return reg
}

func (j *Job) Spec(ctx context.Context, role string, cands []catalog.ModelInfo, reg *tools.Registry) agent.Spec {
	j.ctx = ctx
	return agent.Spec{
		TaskID:     TaskID,
		Role:       role,
		System:     j.system(),
		User:       j.Markdown,
		Tools:      reg.Names(),
		Candidates: cands,
		Check:      j.check,
	}
}

func (j *Job) Result(ctx context.Context) (*Result, error) {
	j.ctx = ctx
	j.evaluate()
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.result == nil {
		if j.err == nil {
			return nil, i18n.E("export.none", j.Format)
		}
		return nil, j.err
	}
	return j.result, nil
}

func (j *Job) system() string {
	return fmt.Sprintf(`Tu convertis un rapport Markdown en document %[1]s avec les outils du serveur MCP %[2]s. Le rapport est le message de l'utilisateur.

Règles :
- Reproduis le texte intégralement et à l'identique : aucun résumé, aucune reformulation, aucune traduction, aucune omission, aucun ajout de contenu. Seule la mise en forme change. Titres, paragraphes, listes, tableaux (en-têtes compris), blocs de code, identifiants de preuves [Exxx], notes et annexes figurent tous dans le document, dans l'ordre du rapport.
- Garde la structure : chaque titre Markdown (annexes comprises) devient un titre du même niveau, à sa place ; ne fusionne jamais une section dans une autre. Une liste reste une liste (numérotée si elle l'est), un tableau un tableau ; un bloc de code devient du texte à chasse fixe si le serveur le permet, sinon un paragraphe à part, jamais un élément de liste.
- Un retour à la ligne dans le texte est un vrai saut de ligne de la chaîne JSON, jamais les deux caractères \n.
- Ne transmets aucune syntaxe Markdown (gras **, code entre accents graves, titres #, tableaux |, liens [texte](url)) dans le texte, sauf si le serveur indique qu'il l'interprète : rends gras, code et liens avec les moyens du serveur, sinon en texte simple (un lien devient « texte (url) »).
- Si le serveur propose un outil de documentation (capacités, syntaxe, guide), appelle-le d'abord et respecte les schémas des outils.
- Titre du document : %[3]s
- Si un appel échoue, corrige les arguments d'après l'erreur et recommence. Si le rapport est trop long pour un seul appel et que le serveur permet d'ajouter des sections à un document existant, crée le document puis complète-le.
- N'utilise que les outils nécessaires à la création de ce document %[1]s.

Réponse finale : une ligne qui indique que le document %[1]s est produit. clotr récupère le fichier à partir des sorties des outils et vérifie que chaque passage du rapport y figure, à sa place, titres rendus comme titres ; en cas d'écart, il te renverra la liste des points à corriger.`, j.Format, j.Server.Name(), j.Title)
}

func (j *Job) noFile() string {
	return fmt.Sprintf("Aucun document %[1]s n'a été obtenu : aucune sortie d'outil ne contient d'URL de téléchargement d'un fichier %[1]s valide. Crée le document avec l'outil adapté du serveur, puis réponds.", j.Format)
}

func (j *Job) check(string) string {
	j.evaluate()
	j.mu.Lock()
	defer j.mu.Unlock()
	switch {
	case j.result == nil && j.err != nil:
		return fmt.Sprintf("Le document n'a pas pu être récupéré (%v). Recrée-le, puis réponds.", j.err)
	case j.result == nil:
		return j.noFile()
	case j.result.Issues() == 0:
		return ""
	}
	r := j.result.Report
	var b strings.Builder
	fmt.Fprintf(&b, "Contrôle automatique du document %s : il ne reproduit pas fidèlement le rapport. Produis-le à nouveau en corrigeant les points suivants, sans rien changer d'autre.\n", j.Format)
	list(&b, "Passages absents ou modifiés (à reprendre mot pour mot)", r.Missing)
	list(&b, "Passages hors de leur place (à remettre dans l'ordre du rapport)", r.Moved)
	list(&b, "Titres du rapport rendus comme texte ordinaire (à rendre comme titres)", r.Flat)
	list(&b, "Syntaxe restée littérale dans le texte (à remplacer par la mise en forme ou le caractère voulu)", r.Artifacts)
	return b.String()
}

func list(b *strings.Builder, title string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%s, %d :\n", title, len(items))
	for _, m := range items[:min(shown, len(items))] {
		fmt.Fprintf(b, "- %s\n", m)
	}
	if n := len(items) - shown; n > 0 {
		fmt.Fprintf(b, "- … et %d autres\n", n)
	}
}

func (j *Job) evaluate() {
	j.mu.Lock()
	cands := j.candidates()
	if len(cands) == 0 || cands[0] == j.fetched {
		j.mu.Unlock()
		return
	}
	j.mu.Unlock()
	var lastErr error
	for _, u := range cands {
		data, err := j.Server.Fetch(j.ctx, u, MaxBytes)
		if err != nil {
			lastErr = err
			continue
		}
		doc, err := Read(j.Format, data)
		if err != nil {
			lastErr = err
			continue
		}
		j.mu.Lock()
		j.fetched, j.result, j.err = cands[0], &Result{Data: data, Report: Compare(j.Markdown, doc)}, nil
		j.mu.Unlock()
		return
	}
	j.mu.Lock()
	j.fetched, j.err = cands[0], lastErr
	j.mu.Unlock()
}

func (j *Job) candidates() []string {
	ext := "." + j.Format
	var exact []string
	for i := len(j.calls) - 1; i >= 0; i-- {
		for _, u := range slices.Backward(j.calls[i]) {
			if p, err := url.Parse(u); err == nil && strings.EqualFold(path.Ext(p.Path), ext) {
				exact = append(exact, u)
			}
		}
	}
	if len(exact) > 0 {
		return exact[:min(len(exact), 3)]
	}
	if n := len(j.calls); n > 0 {
		last := slices.Clone(j.calls[n-1])
		slices.Reverse(last)
		return last[:min(len(last), 5)]
	}
	return nil
}

func (j *Job) record(out string) {
	us := urls(out)
	if len(us) == 0 {
		return
	}
	j.mu.Lock()
	j.calls = append(j.calls, us)
	j.mu.Unlock()
}

type recorder struct {
	tools.Tool
	job *Job
}

func (r *recorder) Call(ctx context.Context, args json.RawMessage) (string, error) {
	out, err := r.Tool.Call(ctx, args)
	if err == nil {
		r.job.record(out)
	}
	return out, err
}

var urlRe = regexp.MustCompile(`https?://[^\s"'<>\\]+`)

func urls(s string) []string {
	var out []string
	add := func(u string) {
		u = strings.TrimRight(u, ".,;)]}")
		if !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	var v any
	if json.Unmarshal([]byte(strings.TrimSpace(s)), &v) == nil {
		var walk func(any)
		walk = func(x any) {
			switch t := x.(type) {
			case string:
				if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
					add(strings.TrimSpace(t))
					return
				}
				for _, u := range urlRe.FindAllString(t, -1) {
					add(u)
				}
			case []any:
				for _, e := range t {
					walk(e)
				}
			case map[string]any:
				keys := make([]string, 0, len(t))
				for k := range t {
					keys = append(keys, k)
				}
				slices.Sort(keys)
				for _, k := range keys {
					walk(t[k])
				}
			}
		}
		walk(v)
		return out
	}
	for _, u := range urlRe.FindAllString(s, -1) {
		add(u)
	}
	return out
}
