package template

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/agardenat/clotr/internal/i18n"
)

type Set struct {
	Dir      string
	byName   map[string]*Template
	Warnings []string
}

func Load(dir string) (*Set, error) {
	s := &Set{Dir: dir, byName: map[string]*Template{}}
	if dir == "" {
		return s, nil
	}
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		s.Warnings = append(s.Warnings, i18n.T("tpl.dir_missing", dir))
		return s, nil
	} else if err != nil {
		return nil, err
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	more, _ := filepath.Glob(filepath.Join(dir, "*.yml"))
	files = append(files, more...)
	sort.Strings(files)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			s.Warnings = append(s.Warnings, fmt.Sprintf("template %s: %v", f, err))
			continue
		}
		t, err := Parse(data, f)
		if err != nil {
			s.Warnings = append(s.Warnings, err.Error()+i18n.T("tpl.ignored"))
			continue
		}
		if prev, ok := s.byName[t.Name]; ok {
			s.Warnings = append(s.Warnings, i18n.T("tpl.name_dup", f, t.Name, prev.Source))
			continue
		}
		s.byName[t.Name] = t
	}
	return s, nil
}

func (s *Set) Get(name string) (*Template, bool) {
	t, ok := s.byName[name]
	return t, ok
}

func (s *Set) All() []*Template {
	out := make([]*Template, 0, len(s.byName))
	for _, n := range sortedKeys(s.byName) {
		out = append(out, s.byName[n])
	}
	return out
}
