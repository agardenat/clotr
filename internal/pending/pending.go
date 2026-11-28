package pending

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

const (
	KindExec   = "exec"
	KindAccess = "access"

	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRefused  = "refused"
	StatusDone     = "done"
	StatusFailed   = "failed"

	FileName = "pending.json"
)

type Item struct {
	ID       int             `json:"id"`
	Kind     string          `json:"kind"`
	Instance string          `json:"instance"`
	Tool     string          `json:"tool"`
	Args     json.RawMessage `json:"args,omitempty"`
	Where    string          `json:"where,omitempty"`
	Argv     []string        `json:"argv,omitempty"`
	Level    string          `json:"level,omitempty"`
	Task     string          `json:"task,omitempty"`
	Reason   string          `json:"reason,omitempty"`
	Status   string          `json:"status"`
	Evidence string          `json:"evidence,omitempty"`
	Error    string          `json:"error,omitempty"`
	Resolved int             `json:"resolved_turn,omitempty"`
}

func (it Item) key() string {
	if it.Kind == KindExec {
		return strings.Join(append([]string{it.Kind, it.Instance, it.Where}, it.Argv...), "\x00")
	}
	return strings.Join([]string{it.Kind, it.Instance, it.Tool, string(it.Args)}, "\x00")
}

type Store struct {
	mu    sync.Mutex
	path  string
	items []Item
}

func (s *Store) Begin(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path, s.items = path, nil
}

func (s *Store) Add(it Item) (Item, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := it.key()
	if i := slices.IndexFunc(s.items, func(x Item) bool { return x.key() == k }); i >= 0 {
		return s.items[i], false, nil
	}
	it.ID, it.Status = len(s.items)+1, StatusPending
	s.items = append(s.items, it)
	if s.path == "" {
		return it, true, nil
	}
	return it, true, Write(s.path, s.items)
}

func (s *Store) Items() []Item {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.items)
}

func Load(path string) ([]Item, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var items []Item
	if err := json.Unmarshal(b, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func Write(path string, items []Item) error {
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func Open(items []Item) []Item {
	return slices.DeleteFunc(slices.Clone(items), func(it Item) bool { return it.Status != StatusPending })
}
