package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/memory"
)

var adjectives = []string{
	"tremendous", "wobbly", "sneaky", "fluffy", "grumpy", "jolly", "mighty", "sleepy", "zesty", "brave",
	"cosmic", "dizzy", "eager", "fancy", "gentle", "happy", "icy", "jumpy", "kind", "lucky",
	"merry", "nimble", "odd", "proud", "quick", "rusty", "shiny", "tiny", "upbeat", "vivid",
	"witty", "young", "zany", "bold", "calm", "daring", "electric", "fuzzy", "giant", "hasty",
	"humble", "lazy", "loud", "mellow", "noisy", "plucky", "quirky", "rapid", "silly", "spicy",
	"stormy", "sturdy", "swift", "tidy", "velvet", "wild", "wise", "crimson", "golden", "silent",
}

var nouns = []string{
	"tentacle", "narwhal", "pickle", "badger", "walrus", "octopus", "penguin", "otter", "llama", "panda",
	"falcon", "gecko", "hedgehog", "iguana", "jellyfish", "koala", "lobster", "meerkat", "newt", "ocelot",
	"platypus", "quokka", "raccoon", "squid", "toucan", "unicorn", "vulture", "wombat", "yak", "zebra",
	"comet", "nebula", "pulsar", "quasar", "geyser", "glacier", "volcano", "tornado", "teapot", "noodle",
	"pretzel", "waffle", "muffin", "bagel", "cactus", "mushroom", "pebble", "acorn", "lantern", "compass",
	"kraken", "goblin", "yeti", "griffin", "dragon", "phoenix", "golem", "sphinx", "banshee", "troll",
}

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

type Turn struct {
	N       int       `json:"n"`
	Time    time.Time `json:"time"`
	Request string    `json:"request"`
	Tools   []string  `json:"tools,omitempty"`
	Status  string    `json:"status"`
	Error   string    `json:"error,omitempty"`
	Models  []string  `json:"models,omitempty"`
	Cost    float64   `json:"cost,omitempty"`
}

type Session struct {
	Name         string    `json:"name"`
	Created      time.Time `json:"created"`
	Updated      time.Time `json:"updated"`
	Confidential bool      `json:"confidential"`
	Sovereign    string    `json:"sovereign,omitempty"`
	Language     string    `json:"language,omitempty"`
	Turns        []Turn    `json:"turns"`
	dir          string
}

func GenerateName(exists func(string) bool) string {
	for range 50 {
		name := adjectives[rand.IntN(len(adjectives))] + "-" + nouns[rand.IntN(len(nouns))]
		if !exists(name) {
			return name
		}
	}
	for i := 2; ; i++ {
		name := fmt.Sprintf("%s-%s-%d", adjectives[rand.IntN(len(adjectives))], nouns[rand.IntN(len(nouns))], i)
		if !exists(name) {
			return name
		}
	}
}

func Create(root string, confidential bool, sovereign string) (*Session, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	name := GenerateName(func(n string) bool {
		_, err := os.Stat(filepath.Join(root, n))
		return err == nil
	})
	now := time.Now()
	s := &Session{Name: name, Created: now, Updated: now, Confidential: confidential, Sovereign: sovereign, dir: filepath.Join(root, name)}
	if err := os.Mkdir(s.dir, 0o700); err != nil {
		return nil, err
	}
	return s, s.Save()
}

func Open(root, name string) (*Session, error) {
	if name == "last" {
		all, err := List(root)
		if err != nil {
			return nil, err
		}
		if len(all) == 0 {
			return nil, errors.New("aucune session")
		}
		return all[0], nil
	}
	if !validName.MatchString(name) {
		return nil, fmt.Errorf("nom de session invalide %q", name)
	}
	return load(filepath.Join(root, name))
}

func load(dir string) (*Session, error) {
	data, err := os.ReadFile(filepath.Join(dir, "session.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("session %s introuvable", filepath.Base(dir))
		}
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("session %s: %w", filepath.Base(dir), err)
	}
	s.dir = dir
	return &s, nil
}

func List(root string) ([]*Session, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []*Session
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if s, err := load(filepath.Join(root, e.Name())); err == nil {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Updated.After(out[j].Updated) })
	return out, nil
}

func (s *Session) Dir() string {
	return s.dir
}

func (s *Session) Save() error {
	s.Updated = time.Now()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.dir, "session.json"), data)
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Session) TurnDir(n int) string {
	return filepath.Join(s.dir, "turns", fmt.Sprintf("%03d", n))
}

func (s *Session) NewTurn(request string) (*Turn, string, error) {
	n := len(s.Turns) + 1
	dir := s.TurnDir(n)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "request.txt"), []byte(request+"\n"), 0o600); err != nil {
		return nil, "", err
	}
	s.Turns = append(s.Turns, Turn{N: n, Time: time.Now(), Request: request, Status: "running"})
	return &s.Turns[n-1], dir, s.Save()
}

func (s *Session) WriteJSON(dir, name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, name), data)
}

func (s *Session) WriteReport(dir, report string) error {
	if err := writeAtomic(filepath.Join(dir, "report.md"), []byte(report)); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.dir, "report.md"), []byte(report))
}

func (s *Session) Report(n int) (string, error) {
	path := filepath.Join(s.dir, "report.md")
	if n > 0 {
		path = filepath.Join(s.TurnDir(n), "report.md")
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	return string(data), err
}

func (s *Session) LoadMemory() ([]memory.Entry, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, "memory.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var snap struct {
		Entries []memory.Entry `json:"entries"`
	}
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("memory.json: %w", err)
	}
	return snap.Entries, nil
}

func (s *Session) SaveMemory(m *memory.Store) error {
	return m.Save(filepath.Join(s.dir, "memory.json"))
}

func (s *Session) History(maxReport int) string {
	var prev []Turn
	for _, t := range s.Turns {
		if t.Status != "running" {
			prev = append(prev, t)
		}
	}
	if len(prev) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Session %s, %d tour(s) précédent(s):\n", s.Name, len(prev))
	for _, t := range prev {
		fmt.Fprintf(&b, "- tour %d (%s, %s): %s\n", t.N, t.Time.Format("2006-01-02 15:04"), t.Status, strings.TrimSpace(t.Request))
	}
	if report, _ := s.Report(0); strings.TrimSpace(report) != "" {
		if maxReport > 0 && len(report) > maxReport {
			report = report[:maxReport] + "\n[rapport tronqué]"
		}
		fmt.Fprintf(&b, "\nDernier rapport de la session:\n%s\n", report)
	}
	return b.String()
}
