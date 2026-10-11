package markdown

import (
	"os"
	"regexp"
	"strings"

	"charm.land/glamour/v2"
	"charm.land/glamour/v2/styles"
	"github.com/charmbracelet/x/ansi"
)

const unwrapped = 4096

var (
	tableSepRe = regexp.MustCompile(`^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$`)
	hangRe     = regexp.MustCompile(`^(\s*)(• |\d+\. )?`)
	frenchSp   = strings.NewReplacer("« ", "«\u00a0", " »", "\u00a0»", " :", "\u00a0:", " ;", "\u00a0;", " ?", "\u00a0?", " !", "\u00a0!")
)

func Style(dark bool) string {
	if s := os.Getenv("GLAMOUR_STYLE"); s != "" {
		return s
	}
	if dark {
		return styles.DarkStyle
	}
	return styles.LightStyle
}

func Render(md string, width int, dark bool) string {
	limit := max(width-4, 20)
	var parts []string
	for _, seg := range segments(md) {
		if seg.table {
			out, ok := render(seg.text, limit, dark)
			if !ok {
				return md
			}
			parts = append(parts, trimBlank(out))
			continue
		}
		out, ok := render(nonBreaking(seg.text), unwrapped, dark)
		if !ok {
			return md
		}
		parts = append(parts, trimBlank(rewrap(out, limit)))
	}
	return strings.Join(parts, "\n\n")
}

func render(md string, wrap int, dark bool) (string, bool) {
	r, err := glamour.NewTermRenderer(glamour.WithStylePath(Style(dark)), glamour.WithWordWrap(wrap), glamour.WithTableWrap(true))
	if err != nil {
		return "", false
	}
	out, err := r.Render(md)
	if err != nil {
		return "", false
	}
	return strings.Trim(out, "\n"), true
}

type segment struct {
	text  string
	table bool
}

func segments(md string) []segment {
	lines := strings.Split(md, "\n")
	var out []segment
	var cur []string
	flush := func(table bool) {
		if strings.TrimSpace(strings.Join(cur, "")) != "" {
			out = append(out, segment{strings.Join(cur, "\n"), table})
		}
		cur = nil
	}
	fence := ""
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		t := strings.TrimSpace(l)
		if fence != "" {
			if strings.HasPrefix(t, fence) {
				fence = ""
			}
			cur = append(cur, l)
			continue
		}
		if strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
			fence = t[:3]
			cur = append(cur, l)
			continue
		}
		if strings.HasPrefix(t, "|") && i+1 < len(lines) && tableSepRe.MatchString(lines[i+1]) {
			flush(false)
			for i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), "|") {
				cur = append(cur, lines[i])
				i++
			}
			i--
			flush(true)
			continue
		}
		cur = append(cur, l)
	}
	flush(false)
	return out
}

func rewrap(s string, limit int) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		plain := ansi.Strip(line)
		w := ansi.StringWidth(strings.TrimRight(plain, " "))
		if w <= limit {
			out = append(out, ansi.Truncate(line, limit, ""))
			continue
		}
		line = ansi.Truncate(line, w, "")
		hang := ansi.StringWidth(hangRe.FindString(plain))
		if hang > limit/2 {
			hang = 0
		}
		head := ansi.Truncate(line, hang, "")
		body := strings.Split(ansi.Wrap(ansi.TruncateLeft(line, hang, ""), limit-hang, " "), "\n")
		pad := strings.Repeat(" ", hang)
		for i, b := range body {
			if i == 0 {
				out = append(out, head+b)
				continue
			}
			out = append(out, pad+strings.TrimLeft(b, " "))
		}
	}
	return strings.Join(out, "\n")
}

func nonBreaking(md string) string {
	lines := strings.Split(md, "\n")
	fence := ""
	for i, l := range lines {
		t := strings.TrimSpace(l)
		switch {
		case fence != "":
			if strings.HasPrefix(t, fence) {
				fence = ""
			}
		case strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~"):
			fence = t[:3]
		default:
			parts := strings.Split(l, "`")
			for j := 0; j < len(parts); j += 2 {
				parts[j] = frenchSp.Replace(parts[j])
			}
			lines[i] = strings.Join(parts, "`")
		}
	}
	return strings.Join(lines, "\n")
}

func trimBlank(s string) string {
	lines := strings.Split(s, "\n")
	blank := func(l string) bool { return strings.TrimSpace(ansi.Strip(l)) == "" }
	for len(lines) > 0 && blank(lines[0]) {
		lines = lines[1:]
	}
	for len(lines) > 0 && blank(lines[len(lines)-1]) {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n")
}
