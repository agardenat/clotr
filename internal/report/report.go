package report

import (
	"embed"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
)

const (
	ModeDefault  = "default"
	ModeCVE      = "cve"
	ModeIncident = "incident"
	ModeChange   = "change"
	ModeUpgrade  = "upgrade"
	ModeWatch    = "watch"
	ModeDAT      = "dat"
	ModeDiagram  = "diagram"
	ModeDocument = "document"
)

var Modes = []string{ModeDefault, ModeCVE, ModeIncident, ModeChange, ModeUpgrade, ModeWatch, ModeDAT, ModeDiagram}

//go:embed models/*.md
var embedded embed.FS

func Model(mode string, overrides map[string]string) (string, error) {
	if !slices.Contains(Modes, mode) {
		return "", fmt.Errorf("mode de rapport %q inconnu (%s)", mode, strings.Join(Modes, ", "))
	}
	if path := overrides[mode]; path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("modèle de rapport %s : %w", mode, err)
		}
		return lf(b), nil
	}
	b, err := embedded.ReadFile("models/" + mode + ".md")
	if err != nil {
		return "", err
	}
	return lf(b), nil
}

func lf(b []byte) string { return strings.ReplaceAll(string(b), "\r\n", "\n") }

var (
	placeholder = regexp.MustCompile(`\{\{\s*([A-Za-z0-9._:-]+)\s*\}\}`)
	comment     = regexp.MustCompile(`(?s)<!--.*?-->`)
	blankLines  = regexp.MustCompile(`\n{3,}`)
)

func Fill(md string, blocks map[string]string, order []string, missingTitle string) (string, []string) {
	index := map[string]string{}
	for k := range blocks {
		index[strings.ToLower(k)] = k
	}
	used := map[string]bool{}
	md = placeholder.ReplaceAllStringFunc(md, func(m string) string {
		key, ok := index[strings.ToLower(placeholder.FindStringSubmatch(m)[1])]
		if !ok || used[key] {
			return ""
		}
		used[key] = true
		return blocks[key]
	})
	md = comment.ReplaceAllString(md, "")
	var missing []string
	var tail strings.Builder
	for _, key := range order {
		if used[key] || strings.TrimSpace(blocks[key]) == "" {
			continue
		}
		missing = append(missing, key)
		tail.WriteString("\n\n" + blocks[key])
	}
	if len(missing) > 0 {
		md = strings.TrimRight(md, "\n") + "\n\n---\n\n## " + missingTitle + tail.String()
	}
	return strings.TrimSpace(blankLines.ReplaceAllString(md, "\n\n")) + "\n", missing
}

var variantMark = regexp.MustCompile(`<!--\s*variant:\s*([a-z0-9_, -]+?)\s*-->\n?`)

type Parts struct {
	Preamble string
	Head     string
	Sections []string
}

func Split(md string) Parts {
	var p Parts
	lines := strings.SplitAfter(md, "\n")
	var cur strings.Builder
	stage := 0
	flush := func() {
		switch stage {
		case 0:
			p.Preamble = strings.TrimSpace(cur.String())
		case 1:
			p.Head = strings.TrimSpace(cur.String())
		default:
			if t := strings.TrimSpace(cur.String()); t != "" {
				p.Sections = append(p.Sections, t)
			}
		}
		cur.Reset()
	}
	for _, l := range lines {
		switch {
		case stage == 0 && strings.HasPrefix(l, "# "):
			flush()
			stage = 1
		case stage >= 1 && strings.HasPrefix(l, "## "):
			flush()
			stage = 2
		}
		cur.WriteString(l)
	}
	flush()
	return p
}

var numbered = regexp.MustCompile(`^## \d+\. `)

func ForVariant(sections []string, variant string) []string {
	var out []string
	for _, s := range sections {
		if m := variantMark.FindStringSubmatch(s); m != nil && !slices.Contains(strings.FieldsFunc(m[1], func(r rune) bool { return r == ',' || r == ' ' }), variant) {
			continue
		}
		s = strings.TrimSpace(variantMark.ReplaceAllString(s, ""))
		if numbered.MatchString(s) {
			s = numbered.ReplaceAllString(s, fmt.Sprintf("## %d. ", len(out)+1))
		}
		out = append(out, s)
	}
	return out
}

func Heading(section string) string {
	first, _, _ := strings.Cut(section, "\n")
	return strings.TrimSpace(strings.TrimLeft(first, "#"))
}
