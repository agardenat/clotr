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
)

var Modes = []string{ModeDefault, ModeCVE, ModeIncident, ModeChange}

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
