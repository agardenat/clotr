package cve

import (
	"path"
	"regexp"
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
	asset, detail string
	cells         [3]string
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
				row = &recapRow{asset: clean(m[1]), detail: trimDetail(clean(m[2]))}
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
	var cards, unknown []string
	for _, s := range subjects {
		cve := strings.Join(s.ids, ", ")
		unknown = append(unknown, unknownLines(s.unknown, cve)...)
		before := len(cards)
		for _, r := range s.rows {
			if r.cells[colMitigation] == "" && r.cells[colFix] == "" {
				continue
			}
			matched := s.cardsFor(r.asset + " " + r.detail)
			why := r.cells[colWhy]
			if why == "" {
				why = r.detail
			}
			if why == "" && len(matched) > 0 {
				why = matched[0].found
			}
			state := stateOf(matched)
			if state == "" {
				state = stateIn(r.asset + " " + r.detail)
			}
			icon, _, _ := strings.Cut(state, " ")
			var c strings.Builder
			c.WriteString("## " + strings.TrimSpace(icon+" "+cve) + " · " + r.asset + "\n\n")
			for _, kv := range [][2]string{
				{i18n.R("cve.recap.state"), state},
				{i18n.R("cve.recap.why"), why},
				{i18n.R("cve.recap.mitigation"), r.cells[colMitigation]},
				{i18n.R("cve.recap.fix"), r.cells[colFix]},
			} {
				c.WriteString("- **" + kv[0] + "**" + colon() + orDash(kv[1]) + "\n")
			}
			cards = append(cards, c.String())
		}
		if len(cards) == before {
			none = append(none, s.ids...)
		}
	}
	for _, c := range cards {
		b.WriteString("\n" + c)
	}
	if len(none) > 0 {
		b.WriteString("\n" + i18n.R("cve.recap.none", strings.Join(none, ", ")) + "\n")
	}
	if len(unknown) > 0 {
		b.WriteString("\n## ❓ " + i18n.R("cve.recap.unknown") + "\n\n")
		b.WriteString(strings.Join(unknown, "\n") + "\n")
	}
	return b.String()
}

func (c *recapCard) level() string {
	e := strings.TrimPrefix(c.exposure, "**")
	for _, x := range []string{Neutralized, Limited, Exposed, Unmeasured} {
		if strings.HasPrefix(e, i18n.R("cve.exp1."+x)) {
			return x
		}
	}
	return ""
}

func stateOf(cards []*recapCard) string {
	var out []string
	for _, x := range exposures {
		for _, c := range cards {
			if c.level() == x {
				out = append(out, ExposureIcon(x)+" "+i18n.R("cve.exp1."+x))
				break
			}
		}
	}
	return strings.Join(out, " · ")
}

func stateIn(text string) string {
	t := fold(text)
	for _, x := range []string{Neutralized, Limited, Exposed} {
		if strings.Contains(t, fold(i18n.R("cve.exp1."+x))) {
			return ExposureIcon(x) + " " + i18n.R("cve.exp1."+x)
		}
	}
	return ""
}

func (s *recapSubject) cardsFor(text string) []*recapCard {
	var out []*recapCard
	for _, c := range s.positive {
		if strings.Contains(text, c.asset) {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		for _, c := range s.positive {
			if i := strings.LastIndex(c.asset, "/"); i >= 0 && len(c.asset)-i > 4 && strings.Contains(text, c.asset[i+1:]) {
				out = append(out, c)
			}
		}
	}
	if len(out) == 0 && len(s.positive) == 1 {
		return s.positive
	}
	return out
}

const groupFrom = 3

func trimDetail(s string) string {
	s = strings.TrimSpace(strings.TrimLeft(s, "—–-: "))
	if strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		s = s[1 : len(s)-1]
	}
	if strings.Count(s, "(") > strings.Count(s, ")") {
		s += ")"
	}
	return strings.TrimSpace(s)
}

func unknownLines(cards []*recapCard, cve string) []string {
	var parents []string
	groups := map[string][]*recapCard{}
	for _, c := range cards {
		p, _ := path.Split(c.asset)
		if _, ok := groups[p]; !ok {
			parents = append(parents, p)
		}
		groups[p] = append(groups[p], c)
	}
	var out []string
	for _, p := range parents {
		g := groups[p]
		if p == "" || len(g) < groupFrom {
			for _, c := range g {
				out = append(out, "- **"+c.asset+"** ("+cve+")"+colon()+orDash(c.missing))
			}
			continue
		}
		var names []string
		for _, c := range g {
			names = append(names, path.Base(c.asset))
		}
		out = append(out, "- **"+strings.TrimSuffix(p, "/")+"** ("+cve+", "+i18n.R("cve.recap.n_assets", len(g))+" : "+strings.Join(names, ", ")+")"+colon()+orDash(g[0].missing))
	}
	return out
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
