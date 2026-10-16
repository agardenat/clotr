package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agardenat/clotr/internal/i18n"
)

type Item struct {
	ID    string    `json:"id"`
	Task  string    `json:"task"`
	Tool  string    `json:"tool"`
	Args  string    `json:"args"`
	Error string    `json:"error,omitempty"`
	Bytes int       `json:"bytes"`
	File  string    `json:"file"`
	Time  time.Time `json:"time"`
}

type Store struct {
	dir    string
	prefix string
	mu     sync.Mutex
	n      int
	items  map[string]Item
	order  []string
	prior  []string
}

var citeRe = regexp.MustCompile(`\bE(?:\d+\.)?\d{3,}\b`)

func Open(dir string, turn int) *Store {
	prefix := "E"
	if turn > 1 {
		prefix = fmt.Sprintf("E%d.", turn)
	}
	return &Store{dir: dir, prefix: prefix, items: map[string]Item{}}
}

func (s *Store) Begin(dir string, turn int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prior = append(s.prior, s.order...)
	s.order, s.n, s.dir = nil, 0, dir
	s.prefix = "E"
	if turn > 1 {
		s.prefix = fmt.Sprintf("E%d.", turn)
	}
}

func (s *Store) Add(task, tool, args, output string, callErr error) string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	s.n++
	id := fmt.Sprintf("%s%03d", s.prefix, s.n)
	s.mu.Unlock()
	it := Item{ID: id, Task: task, Tool: tool, Args: args, Bytes: len(output), File: filepath.Join(s.dir, id+".txt"), Time: time.Now().UTC()}
	if callErr != nil {
		it.Error = callErr.Error()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\ntâche: %s\noutil: %s\narguments: %s\nheure: %s\n", id, task, tool, args, it.Time.Format(time.RFC3339))
	if it.Error != "" {
		fmt.Fprintf(&b, "erreur: %s\n", it.Error)
	}
	b.WriteString("---\n")
	b.WriteString(output)
	if err := os.MkdirAll(s.dir, 0o700); err == nil {
		_ = os.WriteFile(it.File, []byte(b.String()), 0o600)
	}
	s.mu.Lock()
	s.items[id] = it
	s.order = append(s.order, id)
	s.mu.Unlock()
	return id
}

func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.order)
}

func (s *Store) Save() error {
	if s == nil || s.Len() == 0 {
		return nil
	}
	s.mu.Lock()
	list := make([]Item, 0, len(s.order))
	for _, id := range s.order {
		list = append(list, s.items[id])
	}
	s.mu.Unlock()
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, "index.json"), data, 0o600)
}

func (s *Store) Has(id string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.items[id]
	return ok
}

func (s *Store) Proven(text string) bool {
	for _, id := range Cited(text) {
		if s.Has(id) {
			return true
		}
	}
	return false
}

func Cited(text string) []string {
	var out []string
	for _, m := range citeRe.FindAllString(text, -1) {
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

func (s *Store) Annex(report, title, unknown string, display func(string) string) string {
	if s == nil {
		return ""
	}
	ids := Cited(report)
	if len(ids) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n\n---\n\n## %s\n\n", title)
	for _, id := range ids {
		s.mu.Lock()
		it, ok := s.items[id]
		s.mu.Unlock()
		if !ok {
			fmt.Fprintf(&b, "- **%s** : %s\n", id, unknown)
			continue
		}
		args := strings.Join(strings.Fields(it.Args), " ")
		if len(args) > 220 {
			args = args[:220] + "…"
		}
		status := ""
		if it.Error != "" {
			status = " — " + i18n.R("evidence.error")
		}
		fmt.Fprintf(&b, "- **%s** · %s · `%s` `%s`%s → `%s`\n", id, it.Task, it.Tool, args, status, display(it.File))
	}
	return b.String()
}

func Reopen(dir string, turn int) (*Store, error) {
	s := Open(dir, turn)
	list, err := Load(dir)
	if err != nil {
		return nil, err
	}
	for _, it := range list {
		s.items[it.ID] = it
		s.order = append(s.order, it.ID)
	}
	s.n = len(list)
	return s, nil
}

func (s *Store) Import(dir string) error {
	list, err := Load(dir)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, it := range list {
		if _, ok := s.items[it.ID]; ok {
			continue
		}
		if !filepath.IsAbs(it.File) {
			it.File = filepath.Join(dir, filepath.Base(it.File))
		}
		s.items[it.ID] = it
		s.prior = append(s.prior, it.ID)
	}
	return nil
}

func Load(dir string) ([]Item, error) {
	data, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return nil, err
	}
	var list []Item
	return list, json.Unmarshal(data, &list)
}

func Path(sessDir, id string) string {
	turn := 1
	if rest, ok := strings.CutPrefix(id, "E"); ok {
		if n, _, found := strings.Cut(rest, "."); found {
			if v, err := strconv.Atoi(n); err == nil {
				turn = v
			}
		}
	}
	return filepath.Join(sessDir, "turns", fmt.Sprintf("%03d", turn), "evidence", id+".txt")
}

func StripAnnex(report, title string) (string, bool) {
	if i := strings.LastIndex(report, "\n\n---\n\n## "+title+"\n"); i >= 0 {
		return report[:i], true
	}
	return report, false
}

func WithContent(body, sessDir, title, missing string) string {
	ids := Cited(body)
	if len(ids) == 0 {
		return body
	}
	var b strings.Builder
	b.WriteString(body)
	fmt.Fprintf(&b, "\n\n---\n\n## %s\n", title)
	for _, id := range ids {
		data, err := os.ReadFile(Path(sessDir, id))
		if err != nil {
			fmt.Fprintf(&b, "\n- **%s** : %s\n", id, missing)
			continue
		}
		fence := strings.Repeat("`", max(3, longestRun(string(data), '`')+1))
		fmt.Fprintf(&b, "\n### %s\n\n%s\n%s\n%s\n", id, fence, strings.TrimRight(string(data), "\n"), fence)
	}
	return b.String()
}

func longestRun(s string, c rune) int {
	best, cur := 0, 0
	for _, r := range s {
		if r == c {
			cur++
			best = max(best, cur)
		} else {
			cur = 0
		}
	}
	return best
}
