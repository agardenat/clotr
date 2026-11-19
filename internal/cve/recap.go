package cve

import (
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/agardenat/clotr/internal/i18n"
	"golang.org/x/text/unicode/norm"
)

var (
	evidenceRef = regexp.MustCompile(`\s*(\[E\d+\]|\(E\d+\))+`)
	sectionHead = regexp.MustCompile(`^##\s+(\d+)\.`)
	planEntry   = regexp.MustCompile(`^\d+[.)]\s+\*\*(.+?)\*\*\s*:?\s*(.*)$`)
	planBullet  = regexp.MustCompile(`^\s*[-*]\s+(?:\*\*)?([^:*]{2,40}?)(?:\*\*)?\s*:\s*(?:\*\*)?\s*(.*)$`)
	assetHead   = regexp.MustCompile(`^\*\*(?:([^\p{L}\p{N}\s*]+)\s+)?(.+?)\*\*`)
	spaces      = regexp.MustCompile(`\s+`)
)

const (
	colWhy = iota
	colMitigation
	colFix
	colOther
)

type recapCard struct {
	asset, icon, found, exposure, missing string
}

type recapRow struct {
	asset string
	cells [3]string
}

type recapSubject struct {
	ids      []string
	positive []*recapCard
	unknown  []*recapCard
	rows     []*recapRow
}

func Recap(md string) string {
	var subjects []*recapSubject
	var cur *recapSubject
	var row *recapRow
	var card *recapCard
	section, last := "", -1
	for _, l := range strings.Split(md, "\n") {
		t := strings.TrimSpace(l)
		if h, ok := strings.CutPrefix(t, "# "); ok && len(Extract(h)) > 0 {
			cur = &recapSubject{ids: Extract(h)}
			subjects = append(subjects, cur)
			section, row, card = "", nil, nil
			continue
		}
		if cur == nil {
			continue
		}
		if strings.HasPrefix(t, "#") {
			section, row, card = "", nil, nil
			if m := sectionHead.FindStringSubmatch(t); m != nil {
				section = m[1]
			}
			continue
		}
		switch section {
		case "3", "4":
			if m := assetHead.FindStringSubmatch(t); m != nil && !strings.HasPrefix(t, "**"+i18n.R("cve.none_positive")) {
				card = &recapCard{asset: strings.TrimSpace(m[2]), icon: m[1]}
				if section == "3" {
					cur.positive = append(cur.positive, card)
				} else {
					cur.unknown = append(cur.unknown, card)
				}
				continue
			}
			m := planBullet.FindStringSubmatch(t)
			if m == nil || card == nil || !strings.HasPrefix(t, "-") {
				continue
			}
			switch strings.TrimSpace(m[1]) {
			case i18n.R("cve.col.found"):
				card.found = clean(m[2])
			case i18n.R("cve.col.exposure"):
				card.exposure = clean(m[2])
			case i18n.R("cve.col.missing"):
				card.missing = clean(m[2])
			}
		case "6":
			if m := planEntry.FindStringSubmatch(t); m != nil {
				row = &recapRow{asset: clean(m[1])}
				cur.rows = append(cur.rows, row)
				last = -1
				continue
			}
			if row == nil || t == "" {
				continue
			}
			if m := planBullet.FindStringSubmatch(l); m != nil && (strings.HasPrefix(t, "-") || strings.HasPrefix(t, "* ")) {
				last = column(m[1])
				if last != colOther {
					row.cells[last] = join(row.cells[last], clean(m[2]))
				}
				continue
			}
			if last >= 0 && last < colOther {
				row.cells[last] = join(row.cells[last], clean(t))
			}
		}
	}
	if len(subjects) == 0 {
		return ""
	}
	var ids, none []string
	for _, s := range subjects {
		ids = append(ids, s.ids...)
	}
	var b strings.Builder
	b.WriteString("# " + i18n.R("cve.recap.title") + " " + strings.Join(ids, ", ") + "\n")
	var lines, unknown []string
	for _, s := range subjects {
		cve := strings.Join(s.ids, ", ")
		for _, c := range s.unknown {
			unknown = append(unknown, tableRow(cve, c.asset, c.missing))
		}
		if len(s.rows) == 0 {
			none = append(none, s.ids...)
			continue
		}
		for _, r := range s.rows {
			cards := s.cardsFor(r.asset)
			why := r.cells[colWhy]
			if why == "" {
				why = cardsText(cards, func(c *recapCard) string { return c.found })
			}
			state := cardsText(cards, func(c *recapCard) string { return strings.TrimSpace(c.stateIcon() + " " + c.exposure) })
			lines = append(lines, tableRow(cve, r.asset, state, why, r.cells[colMitigation], r.cells[colFix]))
		}
	}
	if len(lines) > 0 {
		b.WriteString("\n" + tableHead("CVE", i18n.R("cve.recap.asset"), i18n.R("cve.recap.state"), i18n.R("cve.recap.why"), i18n.R("cve.recap.mitigation"), i18n.R("cve.recap.fix")))
		b.WriteString(strings.Join(lines, "\n") + "\n")
	}
	if len(none) > 0 {
		b.WriteString("\n" + i18n.R("cve.recap.none", strings.Join(none, ", ")) + "\n")
	}
	if len(unknown) > 0 {
		b.WriteString("\n## ❓ " + i18n.R("cve.recap.unknown") + "\n\n")
		b.WriteString(tableHead("CVE", i18n.R("cve.recap.asset"), i18n.R("cve.col.missing")))
		b.WriteString(strings.Join(unknown, "\n") + "\n")
	}
	return b.String()
}

func (c *recapCard) stateIcon() string {
	e := strings.TrimPrefix(c.exposure, "**")
	for _, x := range []string{Neutralized, Limited, Exposed, Unmeasured} {
		if strings.HasPrefix(e, i18n.R("cve.exp1."+x)) {
			return ExposureIcon(x)
		}
	}
	return c.icon
}

func (s *recapSubject) cardsFor(title string) []*recapCard {
	var out []*recapCard
	for _, c := range s.positive {
		if strings.Contains(title, c.asset) {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return s.positive
	}
	return out
}

func cardsText(cards []*recapCard, get func(*recapCard) string) string {
	var vals []string
	for _, c := range cards {
		if v := get(c); v != "" && !slices.Contains(vals, v) {
			vals = append(vals, v)
		}
	}
	if len(vals) <= 1 {
		return strings.Join(vals, "")
	}
	vals = vals[:0]
	for _, c := range cards {
		if v := get(c); v != "" {
			vals = append(vals, c.asset+" : "+v)
		}
	}
	return strings.Join(vals, " ; ")
}

func tableHead(cols ...string) string {
	return "| " + strings.Join(cols, " | ") + " |\n" + strings.Repeat("|---", len(cols)) + "|\n"
}

func tableRow(cells ...string) string {
	for i, c := range cells {
		if c == "" {
			c = "—"
		}
		cells[i] = strings.ReplaceAll(c, "|", `\|`)
	}
	return "| " + strings.Join(cells, " | ") + " |"
}

func column(label string) int {
	l := fold(label)
	switch {
	case strings.Contains(l, "pourquoi") || strings.Contains(l, "why") || strings.Contains(l, "constat") || strings.Contains(l, "trouve") || strings.Contains(l, "found"):
		return colWhy
	case strings.Contains(l, "mitigation") || strings.Contains(l, "contournement") || strings.Contains(l, "workaround") || strings.Contains(l, "palliati"):
		return colMitigation
	case strings.Contains(l, "correcti") || strings.Contains(l, "fix") || strings.Contains(l, "patch") || strings.Contains(l, "remediation"):
		return colFix
	}
	return colOther
}

func fold(s string) string {
	var b strings.Builder
	for _, r := range norm.NFD.String(strings.ToLower(s)) {
		if !unicode.Is(unicode.Mn, r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func clean(s string) string {
	s = evidenceRef.ReplaceAllString(s, "")
	s = strings.TrimSpace(spaces.ReplaceAllString(s, " "))
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, "**"), "**"))
	return strings.ReplaceAll(s, "**", "")
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + " " + b
}
