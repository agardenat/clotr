package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/agardenat/clotr/internal/tools"
)

const (
	ToolName   = "evidence_read"
	SearchName = "evidence_search"
)

type readTool struct{ s *Store }

func (s *Store) Tool() tools.Tool { return readTool{s} }

func (s *Store) SearchTool() tools.Tool { return searchTool{s} }

type searchTool struct{ s *Store }

func (searchTool) Name() string { return SearchName }

func (searchTool) Description() string {
	return "Cherche parmi les preuves déjà collectées dans la session (tous les tours) avant de refaire un appel : termes cherchés dans l'outil et ses arguments (cible, hôte, chemin, service), au moins un terme requis, les preuves qui en contiennent le plus d'abord. content filtre en plus sur le contenu (expression régulière). Chaque résultat donne l'identifiant, l'heure de collecte, l'outil, les arguments et la taille : relire ensuite avec evidence_read, et ne recollecter que si la donnée a pu changer depuis."
}

func (searchTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"terms":{"type":"array","items":{"type":"string"},"description":"ex: [\"app\", \"master1\", \"ssh_list\"]"},"content":{"type":"string","description":"expression régulière sur le contenu archivé (syntaxe RE2 : pas de lookahead (?!…) ni de référence arrière)"},"limit":{"type":"integer","description":"résultats affichés (30 par défaut)"}},"required":["terms"]}`)
}

func (t searchTool) Call(_ context.Context, raw json.RawMessage) (string, error) {
	a, err := tools.Decode[struct {
		Terms   tools.StringList `json:"terms"`
		Content string           `json:"content"`
		Limit   int              `json:"limit"`
	}](raw)
	if err != nil {
		return "", err
	}
	var re *regexp.Regexp
	if a.Content != "" {
		if re, err = regexp.Compile(a.Content); err != nil {
			return "", fmt.Errorf("content invalide: %w", err)
		}
	}
	t.s.mu.Lock()
	items := make([]Item, 0, len(t.s.items))
	for _, it := range t.s.items {
		items = append(items, it)
	}
	t.s.mu.Unlock()
	type hit struct {
		it    Item
		score int
	}
	var hits []hit
	for _, it := range items {
		hay := strings.ToLower(it.Tool + " " + it.Args + " " + it.Task)
		score := 0
		for _, term := range a.Terms {
			if term = strings.ToLower(strings.TrimSpace(term)); term != "" && strings.Contains(hay, term) {
				score++
			}
		}
		if score == 0 {
			continue
		}
		if re != nil {
			data, err := os.ReadFile(it.File)
			if err != nil || !re.Match(data) {
				continue
			}
		}
		hits = append(hits, hit{it, score})
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		return hits[i].it.Time.After(hits[j].it.Time)
	})
	limit := a.Limit
	if limit <= 0 {
		limit = 30
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d preuves correspondent (sur %d dans la session)\n", len(hits), len(items))
	for _, h := range hits[:min(len(hits), limit)] {
		args := strings.Join(strings.Fields(h.it.Args), " ")
		if len(args) > 200 {
			args = args[:200] + "…"
		}
		status := ""
		if h.it.Error != "" {
			status = " · erreur"
		}
		fmt.Fprintf(&b, "%s · %s · %s %s · %d octets%s\n", h.it.ID, h.it.Time.UTC().Format("2006-01-02 15:04Z"), h.it.Tool, args, h.it.Bytes, status)
	}
	return b.String(), nil
}

func (readTool) Name() string { return ToolName }

func (readTool) Description() string {
	return "Relit la sortie complète d'un appel d'outil déjà archivée sous son identifiant de preuve (ex: E012), sans refaire l'appel. Utile quand une sortie a été raccourcie dans l'historique. pattern filtre les lignes (expression régulière), sinon offset/lines choisissent une plage."
}

func (readTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"id":{"type":"string","description":"identifiant de preuve, ex: E012 ou E2.005"},"pattern":{"type":"string","description":"expression régulière (syntaxe RE2 : pas de lookahead (?!…) ni de référence arrière) : seules les lignes correspondantes sont renvoyées"},"offset":{"type":"integer","description":"première ligne (1 par défaut)"},"lines":{"type":"integer","description":"nombre de lignes (200 par défaut)"}},"required":["id"]}`)
}

func (t readTool) Call(_ context.Context, raw json.RawMessage) (string, error) {
	a, err := tools.Decode[struct {
		ID      string `json:"id"`
		Pattern string `json:"pattern"`
		Offset  int    `json:"offset"`
		Lines   int    `json:"lines"`
	}](raw)
	if err != nil {
		return "", err
	}
	id := strings.Trim(strings.TrimSpace(a.ID), "[]")
	t.s.mu.Lock()
	it, ok := t.s.items[id]
	t.s.mu.Unlock()
	if !ok {
		return "", fmt.Errorf("preuve %s inconnue dans ce run", id)
	}
	data, err := os.ReadFile(it.File)
	if err != nil {
		return "", err
	}
	body := string(data)
	if _, rest, found := strings.Cut(body, "\n---\n"); found {
		body = rest
	}
	all := strings.Split(body, "\n")
	limit := a.Lines
	if limit <= 0 {
		limit = 200
	}
	var b strings.Builder
	if a.Pattern != "" {
		re, err := regexp.Compile(a.Pattern)
		if err != nil {
			return "", fmt.Errorf("pattern invalide: %w", err)
		}
		n := 0
		for i, l := range all {
			if !re.MatchString(l) {
				continue
			}
			n++
			if n <= limit {
				fmt.Fprintf(&b, "%d: %s\n", i+1, l)
			}
		}
		return fmt.Sprintf("%s (%s) : %d lignes sur %d correspondent\n%s", id, it.Tool, n, len(all), b.String()), nil
	}
	from := max(a.Offset, 1)
	if from > len(all) {
		return fmt.Sprintf("%s (%s) : %d lignes, offset %d hors limites", id, it.Tool, len(all), from), nil
	}
	to := min(from-1+limit, len(all))
	for i := from - 1; i < to; i++ {
		fmt.Fprintf(&b, "%d: %s\n", i+1, all[i])
	}
	return fmt.Sprintf("%s (%s) : lignes %d à %d sur %d\n%s", id, it.Tool, from, to, len(all), b.String()), nil
}
