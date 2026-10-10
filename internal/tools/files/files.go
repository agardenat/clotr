package files

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/tools"
)

const (
	maxListEntries = 1000
	maxLineChars   = 300
)

type FS struct {
	roots    []string
	maxBytes int
}

func New(cfg *config.Files) (*FS, []string, error) {
	f := &FS{maxBytes: cfg.MaxFileBytes}
	var warnings []string
	for _, r := range cfg.Roots {
		abs, err := filepath.Abs(r)
		if err == nil {
			abs, err = filepath.EvalSymlinks(abs)
		}
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("files: racine ignorée %s: %v", r, err))
			continue
		}
		f.roots = append(f.roots, abs)
	}
	if len(f.roots) == 0 {
		return nil, warnings, errors.New("files: aucune racine accessible")
	}
	return f, warnings, nil
}

func (f *FS) Tools() []tools.Tool {
	return []tools.Tool{listTool{f}, readTool{f}, grepTool{f}}
}

func (f *FS) within(p string) bool {
	for _, r := range f.roots {
		if p == r {
			return true
		}
		prefix := r
		if !strings.HasSuffix(prefix, string(filepath.Separator)) {
			prefix += string(filepath.Separator)
		}
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func (f *FS) resolve(p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("chemin absolu requis: %q", p)
	}
	real, err := filepath.EvalSymlinks(filepath.Clean(p))
	if err != nil {
		return "", err
	}
	if !f.within(real) {
		return "", fmt.Errorf("%s hors des racines autorisées (%s)", p, strings.Join(f.roots, ", "))
	}
	return real, nil
}

func (f *FS) rootsDesc() string {
	return "Racines autorisées: " + strings.Join(f.roots, ", ") + "."
}

func isBinary(head []byte) bool {
	return bytes.IndexByte(head, 0) >= 0
}

type listTool struct{ f *FS }

func (listTool) Name() string { return "fs_list" }
func (t listTool) Description() string {
	return "Liste le contenu d'un répertoire local (lecture seule). " + t.f.rootsDesc()
}
func (listTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"chemin absolu"},"depth":{"type":"integer","description":"profondeur 1-5, défaut 1"}},"required":["path"]}`)
}

func (t listTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	args, err := tools.Decode[struct {
		Path  string `json:"path"`
		Depth int    `json:"depth"`
	}](raw)
	if err != nil {
		return "", err
	}
	depth := min(max(args.Depth, 1), 5)
	root, err := t.f.resolve(args.Path)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	n := 0
	base := strings.Count(root, string(filepath.Separator))
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			fmt.Fprintf(&b, "! %s: %v\n", p, err)
			return nil
		}
		if p == root {
			return nil
		}
		if strings.Count(p, string(filepath.Separator))-base > depth {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if n >= maxListEntries {
			return fs.SkipAll
		}
		n++
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, _ := os.Readlink(p)
			fmt.Fprintf(&b, "l %s -> %s\n", p, target)
		case d.IsDir():
			fmt.Fprintf(&b, "d %s/\n", p)
		default:
			size := int64(-1)
			if info, err := d.Info(); err == nil {
				size = info.Size()
			}
			fmt.Fprintf(&b, "f %s %d\n", p, size)
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.SkipAll) {
		return "", err
	}
	if n >= maxListEntries {
		fmt.Fprintf(&b, "[limite de %d entrées atteinte]\n", maxListEntries)
	}
	return b.String(), nil
}

type readTool struct{ f *FS }

func (readTool) Name() string { return "fs_read" }
func (t readTool) Description() string {
	return "Lit un fichier texte local (lecture seule), par plage de lignes. " + t.f.rootsDesc()
}
func (readTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"path":{"type":"string","description":"chemin absolu"},"offset":{"type":"integer","description":"première ligne (1-based), défaut 1"},"limit":{"type":"integer","description":"nombre de lignes, défaut 400"}},"required":["path"]}`)
}

func (t readTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	args, err := tools.Decode[struct {
		Path   string `json:"path"`
		Offset int    `json:"offset"`
		Limit  int    `json:"limit"`
	}](raw)
	if err != nil {
		return "", err
	}
	p, err := t.f.resolve(args.Path)
	if err != nil {
		return "", err
	}
	fh, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	info, err := fh.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s n'est pas un fichier régulier", p)
	}
	br := bufio.NewReader(fh)
	head, _ := br.Peek(8192)
	if isBinary(head) {
		return "", fmt.Errorf("%s est un fichier binaire", p)
	}
	offset := max(args.Offset, 1)
	limit := args.Limit
	if limit <= 0 {
		limit = 400
	}
	var b strings.Builder
	line, read := 0, 0
	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		s, err := br.ReadString('\n')
		if s != "" {
			line++
			if line >= offset {
				if read >= limit || b.Len() >= t.f.maxBytes {
					fmt.Fprintf(&b, "[suite à partir de la ligne %d]\n", line)
					break
				}
				fmt.Fprintf(&b, "%6d\t%s", line, strings.TrimRight(s, "\n")+"\n")
				read++
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

type grepTool struct{ f *FS }

func (grepTool) Name() string { return "fs_grep" }
func (t grepTool) Description() string {
	return "Recherche une regex (RE2) dans les fichiers texte d'un répertoire local (lecture seule). " + t.f.rootsDesc()
}
func (grepTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"pattern":{"type":"string","description":"regex RE2"},"path":{"type":"string","description":"fichier ou répertoire absolu"},"glob":{"type":"string","description":"filtre sur le nom de fichier, ex: *.xml"},"ignore_case":{"type":"boolean"},"max_matches":{"type":"integer","description":"défaut 200"}},"required":["pattern","path"]}`)
}

func (t grepTool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	args, err := tools.Decode[struct {
		Pattern    string `json:"pattern"`
		Path       string `json:"path"`
		Glob       string `json:"glob"`
		IgnoreCase bool   `json:"ignore_case"`
		MaxMatches int    `json:"max_matches"`
	}](raw)
	if err != nil {
		return "", err
	}
	pat := args.Pattern
	if args.IgnoreCase {
		pat = "(?i)" + pat
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return "", err
	}
	if args.Glob != "" {
		if _, err := filepath.Match(args.Glob, "x"); err != nil {
			return "", fmt.Errorf("glob invalide: %w", err)
		}
	}
	maxMatches := args.MaxMatches
	if maxMatches <= 0 {
		maxMatches = 200
	}
	root, err := t.f.resolve(args.Path)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	matches := 0
	grepFile := func(p string) {
		real, err := t.f.resolve(p)
		if err != nil {
			return
		}
		info, err := os.Stat(real)
		if err != nil || !info.Mode().IsRegular() || info.Size() > int64(t.f.maxBytes) {
			return
		}
		data, err := os.ReadFile(real)
		if err != nil || isBinary(data[:min(len(data), 8192)]) {
			return
		}
		for i, l := range strings.Split(string(data), "\n") {
			if matches >= maxMatches {
				return
			}
			if re.MatchString(l) {
				matches++
				if len(l) > maxLineChars {
					l = l[:maxLineChars] + "…"
				}
				fmt.Fprintf(&b, "%s:%d: %s\n", p, i+1, l)
			}
		}
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil || matches >= maxMatches {
			if matches >= maxMatches {
				return fs.SkipAll
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if args.Glob != "" {
			if ok, _ := filepath.Match(args.Glob, d.Name()); !ok {
				return nil
			}
		}
		grepFile(p)
		return nil
	})
	if err != nil && !errors.Is(err, fs.SkipAll) {
		return "", err
	}
	if matches == 0 {
		return "aucune correspondance", nil
	}
	if matches >= maxMatches {
		fmt.Fprintf(&b, "[limite de %d correspondances atteinte]\n", maxMatches)
	}
	return b.String(), nil
}
