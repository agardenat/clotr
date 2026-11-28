package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"

	"github.com/agardenat/clotr/internal/i18n"
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

var adjectivesFR = []string{
	"fieffe", "sacre", "satane", "fichu", "fameux", "illustre", "vieux", "gros", "petit", "grand",
	"pauvre", "drole", "joyeux", "fier", "affreux", "terrible", "redoutable", "incorrigible", "irresistible", "sublime",
	"vaillant", "fringant", "pimpant", "bougon", "grincheux", "ronchon", "farfelu", "loufoque", "saugrenu", "fougueux",
	"intrepide", "malicieux", "espiegle", "facetieux", "dodu", "joufflu", "ventru", "chafouin", "goguenard", "hirsute",
	"ebouriffe", "debonnaire", "guilleret", "foufou", "zinzin", "maboul", "ahuri", "patibulaire", "truculent", "pompeux",
	"mysterieux", "distingue", "ombrageux", "paresseux", "gourmand", "tonitruant", "bedonnant", "cocasse", "flamboyant", "foutraque",
}

var nounsFR = []string{
	"coquin", "chenapan", "galopin", "garnement", "filou", "gredin", "fripon", "sacripant", "malandrin", "brigand",
	"vaurien", "bougre", "zigoto", "olibrius", "hurluberlu", "energumene", "escogriffe", "pignouf", "lascar", "loustic",
	"zouave", "nigaud", "dadais", "gugusse", "farfadet", "lutin", "gnome", "troll", "golem", "griffon",
	"kraken", "yeti", "sphinx", "dragon", "cornichon", "saucisson", "camembert", "croissant", "cassoulet", "artichaut",
	"poireau", "navet", "radis", "bigorneau", "homard", "blaireau", "herisson", "ornithorynque", "lama", "morse",
	"poulpe", "ecureuil", "hibou", "canard", "dindon", "pingouin", "escargot", "crapaud", "ouistiti", "phacochere",
}

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

type Turn struct {
	N        int       `json:"n"`
	Time     time.Time `json:"time"`
	Request  string    `json:"request"`
	Tools    []string  `json:"tools,omitempty"`
	Exclude  []string  `json:"exclude,omitempty"`
	Access   string    `json:"access,omitempty"`
	CVE      []string  `json:"cve,omitempty"`
	Mode     string    `json:"mode,omitempty"`
	DAT      string    `json:"dat,omitempty"`
	Ticket   string    `json:"ticket,omitempty"`
	Clients  []string  `json:"clients,omitempty"`
	Projects []string  `json:"projects,omitempty"`
	Status   string    `json:"status"`
	Error    string    `json:"error,omitempty"`
	Models   []string  `json:"models,omitempty"`
	Cost     float64   `json:"cost,omitempty"`
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
	root         string
}

func nameWords() ([]string, []string) {
	if i18n.UI() == "fr" {
		return adjectivesFR, nounsFR
	}
	return adjectives, nouns
}

func GenerateName(exists func(string) bool) string {
	return GenerateNamePrefixed("", exists)
}

func GenerateNamePrefixed(prefix string, exists func(string) bool) string {
	adj, noun := nameWords()
	for range 50 {
		name := prefix + adj[rand.IntN(len(adj))] + "-" + noun[rand.IntN(len(noun))]
		if !exists(name) {
			return name
		}
	}
	for i := 2; ; i++ {
		name := fmt.Sprintf("%s%s-%s-%d", prefix, adj[rand.IntN(len(adj))], noun[rand.IntN(len(noun))], i)
		if !exists(name) {
			return name
		}
	}
}

var namePart = regexp.MustCompile(`[^a-z0-9]+`)

func NamePrefix(parts ...string) string {
	var out []string
	for _, p := range parts {
		p = strings.Trim(namePart.ReplaceAllString(strings.ToLower(foldAccents(p)), "-"), "-")
		if p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "-") + "-"
}

func foldAccents(s string) string {
	var b strings.Builder
	for _, r := range norm.NFD.String(s) {
		if !unicode.Is(unicode.Mn, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func New(root string, confidential bool, sovereign string) *Session {
	now := time.Now()
	return &Session{Created: now, Updated: now, Confidential: confidential, Sovereign: sovereign, root: root}
}

func (s *Session) Started() bool {
	return s.dir != ""
}

func (s *Session) Start(prefix string) error {
	if s.Started() {
		return nil
	}
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return err
	}
	for {
		name := GenerateNamePrefixed(prefix, func(n string) bool {
			_, err := os.Lstat(filepath.Join(s.root, n))
			return err == nil
		})
		dir := filepath.Join(s.root, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return err
		}
		s.Name, s.dir = name, dir
		return s.Save()
	}
}

func Create(root string, confidential bool, sovereign string) (*Session, error) {
	s := New(root, confidential, sovereign)
	return s, s.Start("")
}

func Open(root, name string) (*Session, error) {
	if name == "last" {
		all, err := List(root)
		if err != nil {
			return nil, err
		}
		if len(all) == 0 {
			return nil, i18n.E("session.none")
		}
		return all[0], nil
	}
	if !validName.MatchString(name) {
		return nil, i18n.E("session.invalid_name", name)
	}
	return load(filepath.Join(root, name))
}

func load(dir string) (*Session, error) {
	data, err := os.ReadFile(filepath.Join(dir, "session.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, i18n.E("session.not_found", filepath.Base(dir))
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

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9-]+`)

func (t Turn) ReportName() string { return t.name("") }

func (t Turn) RecapName() string { return t.name("RECAP") }

func (t Turn) ClientRecapName(names []string) string {
	t.Projects, t.Clients = nil, names
	return t.name("RECAP")
}

func (t Turn) name(suffix string) string {
	var kind string
	switch {
	case len(t.CVE) > 0:
		ids := make([]string, len(t.CVE))
		for i, id := range t.CVE {
			ids[i] = strings.TrimPrefix(strings.ToUpper(id), "CVE-")
		}
		kind = "CVE-" + strings.Join(ids, "+")
	case t.Mode == "dat":
		kind = "DAT"
	case t.Mode == "diagram":
		kind = "DIAGRAM"
	case t.Mode == "minutes":
		kind = "CR"
	default:
		return "report"
	}
	var parts []string
	for _, c := range append(slices.Clone(t.Projects), t.Clients...) {
		if c = strings.Trim(unsafeName.ReplaceAllString(strings.ToUpper(foldAccents(c)), "-"), "-"); c != "" && !slices.Contains(parts, c) {
			parts = append(parts, c)
		}
	}
	parts = append(parts, kind)
	if suffix != "" {
		parts = append(parts, suffix)
	}
	return strings.Join(append(parts, t.Time.Local().Format("20060102")), "_")
}

func (s *Session) RecapPath(n int, ext string) string {
	return filepath.Join(s.TurnDir(n), s.Turns[n-1].RecapName()+"."+ext)
}

func (s *Session) ReportPath(n int, ext string) string {
	return filepath.Join(s.TurnDir(n), s.Turns[n-1].ReportName()+"."+ext)
}

func (s *Session) WriteReport(n int, report string) error {
	if err := writeAtomic(s.ReportPath(n, "md"), []byte(report)); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.dir, "report.md"), []byte(report))
}

func (s *Session) Report(n int) (string, error) {
	paths := []string{filepath.Join(s.dir, "report.md")}
	if n > 0 {
		paths = []string{s.ReportPath(n, "md"), filepath.Join(s.TurnDir(n), "report.md")}
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		return string(data), err
	}
	return "", nil
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
