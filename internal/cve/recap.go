package cve

import (
	"regexp"
	"slices"
	"strings"

	"github.com/agardenat/clotr/internal/i18n"
)

var (
	evidenceRef = regexp.MustCompile(`\s*(\[E\d+\])+`)
	sectionHead = regexp.MustCompile(`^##\s+(\d+)\.`)
)

type recapSubject struct {
	title     string
	positives []string
	fixes     []string
}

func Recap(md string) string {
	var subjects []*recapSubject
	var cur *recapSubject
	var dst *[]string
	for _, l := range strings.Split(md, "\n") {
		t := strings.TrimSpace(l)
		if h, ok := strings.CutPrefix(t, "# "); ok && len(Extract(h)) > 0 {
			cur = &recapSubject{title: strings.TrimSpace(h)}
			subjects = append(subjects, cur)
			dst = nil
			continue
		}
		if cur == nil {
			continue
		}
		if strings.HasPrefix(t, "#") {
			dst = nil
			if m := sectionHead.FindStringSubmatch(t); m != nil {
				switch m[1] {
				case "3":
					dst = &cur.positives
				case "6":
					dst = &cur.fixes
				}
			}
			continue
		}
		if dst != nil {
			*dst = append(*dst, evidenceRef.ReplaceAllString(l, ""))
		}
	}
	if len(subjects) == 0 {
		return ""
	}
	var ids []string
	for _, s := range subjects {
		ids = append(ids, Extract(s.title)...)
	}
	drop := []string{i18n.R("cve.col.test"), i18n.R("cve.l.other_checks"), i18n.R("cve.col.evidence")}
	var b strings.Builder
	b.WriteString("# " + i18n.R("cve.recap.title") + " " + strings.Join(ids, ", ") + "\n")
	for _, s := range subjects {
		b.WriteString("\n## " + s.title + "\n\n")
		pos := section(slices.DeleteFunc(s.positives, func(l string) bool {
			t := strings.TrimSpace(l)
			return slices.ContainsFunc(drop, func(label string) bool { return strings.HasPrefix(t, "- **"+label+"**") })
		}))
		if pos == "" || strings.HasPrefix(pos, i18n.R("cve.none_positive")) {
			b.WriteString(i18n.R("cve.none_positive") + "\n")
			continue
		}
		b.WriteString("### " + i18n.R("cve.recap.positives") + "\n\n" + pos + "\n")
		if fixes := section(s.fixes); fixes != "" {
			b.WriteString("\n### " + i18n.R("cve.recap.fixes") + "\n\n" + fixes + "\n")
		}
	}
	return b.String()
}

func section(lines []string) string {
	for len(lines) > 0 {
		t := strings.TrimSpace(lines[len(lines)-1])
		if t != "" && t != "---" {
			break
		}
		lines = lines[:len(lines)-1]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
