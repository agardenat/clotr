package cve

import (
	"cmp"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/agardenat/clotr/internal/access"
	"github.com/agardenat/clotr/internal/cve/sources"
	"github.com/agardenat/clotr/internal/i18n"
)

const (
	BlockVerdict   = "verdict"
	BlockFiche     = "fiche"
	BlockPositives = "positives"
	BlockUnknown   = "unknown"
	BlockNegatives = "negatives"
	maxTests       = 3
	maxProofs      = 6
	maxTestLen     = 160
)

var BlockNames = []string{BlockVerdict, BlockFiche, BlockPositives, BlockUnknown, BlockNegatives}

func BlockKey(id, name string) string { return "cve." + id + "." + name }

func (s *Store) Blocks() (map[string]string, []string) {
	advs, finds := s.Advisories(), s.Findings()
	blocks := map[string]string{}
	var order []string
	for _, id := range s.IDs {
		var adv *Advisory
		for i := range advs {
			if advs[i].CVE == id {
				adv = &advs[i]
			}
		}
		var mine []Finding
		for _, f := range finds {
			if f.CVE == id {
				mine = append(mine, f)
			}
		}
		for _, name := range BlockNames {
			key := BlockKey(id, name)
			order = append(order, key)
			switch name {
			case BlockVerdict:
				blocks[key] = verdict(mine)
			case BlockFiche:
				blocks[key] = s.fiche(id, adv, mine)
			case BlockPositives:
				blocks[key] = s.positives(adv, mine)
			case BlockUnknown:
				blocks[key] = s.unknowns(mine)
			case BlockNegatives:
				blocks[key] = s.negatives(mine)
			}
		}
	}
	return blocks, order
}

func decimal(v float64, prec int) string {
	s := strconv.FormatFloat(v, 'f', prec, 64)
	if i18n.Report() == "fr" {
		s = strings.Replace(s, ".", ",", 1)
	}
	return s
}

func percent(v float64) string {
	p := v * 100
	if p >= 99.95 && v < 1 {
		return "> " + decimal(99.9, 1)
	}
	return decimal(math.Round(p*10)/10, 1)
}

func epssLine(e *sources.EPSSData) string {
	if e == nil {
		return ""
	}
	return i18n.R("cve.epss", percent(e.Score), percent(e.Percentile), e.Date)
}

func kevLine(f *sources.Facts) string {
	switch {
	case f.KEV != nil:
		s := i18n.R("cve.kev.in", f.KEV.DateAdded)
		if f.KEV.DueDate != "" {
			s += i18n.R("cve.kev.due", f.KEV.DueDate)
		}
		if f.KEV.Ransomware != "" {
			s += i18n.R("cve.kev.ransomware", f.KEV.Ransomware)
		}
		return s
	case f.KEVChecked:
		return i18n.R("cve.kev.out")
	}
	return i18n.R("cve.kev.unchecked")
}

func ssvcLine(v string) string {
	if v == "" {
		return ""
	}
	if l := i18n.R("cve.ssvc." + v); l != "cve.ssvc."+v {
		return l
	}
	return v
}

func exploitLine(f *sources.Facts) string {
	if f == nil {
		return ""
	}
	parts := []string{"CISA KEV : " + kevLine(f)}
	if f.SSVC != "" {
		parts = append(parts, "SSVC : "+ssvcLine(f.SSVC))
	}
	if e := epssLine(f.EPSS); e != "" {
		parts = append(parts, "EPSS : "+e)
	}
	return strings.Join(parts, " · ")
}

var scorePriority = []string{"NVD", "CNA", "GitHub", "Red Hat", "CISA ADP", "Ubuntu"}

func MainScore(f *sources.Facts) string {
	if f == nil || len(f.Scores) == 0 {
		return ""
	}
	rank := func(sc sources.Score) int {
		for i, p := range scorePriority {
			if strings.HasPrefix(sc.Source, p) {
				r := i * 2
				if !strings.HasPrefix(sc.Version, "3") {
					r++
				}
				return r
			}
		}
		return 100
	}
	best := slices.MinFunc(f.Scores, func(a, b sources.Score) int { return cmp.Compare(rank(a), rank(b)) })
	return fmt.Sprintf("CVSS %s %.1f %s", best.Version, best.Score, best.Severity)
}

func severityLabel(sev string) string {
	if l := i18n.R("cve.sev." + strings.ToLower(sev)); !strings.HasPrefix(l, "cve.sev.") {
		return l
	}
	return sev
}

func decodeVector(vector string) string {
	metrics := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		if k, v, ok := strings.Cut(part, ":"); ok {
			metrics[k] = v
		}
	}
	var out []string
	for _, k := range []string{"AV", "AC", "AT", "PR", "UI"} {
		v, ok := metrics[k]
		if !ok {
			continue
		}
		if l := i18n.R("cvss." + k + "." + v); !strings.HasPrefix(l, "cvss.") {
			out = append(out, l)
		}
	}
	return strings.Join(out, ", ")
}

func evidenceOf(f *sources.Facts, name string) string {
	if src, ok := f.SourceOf(name); ok && src.Evidence != "" {
		return "[" + src.Evidence + "]"
	}
	return ""
}

func (s *Store) fiche(id string, adv *Advisory, finds []Finding) string {
	var b strings.Builder
	if adv == nil {
		b.WriteString(i18n.R("cve.no_fiche"))
		return b.String()
	}
	f := adv.Facts
	h := func(title string) { b.WriteString("\n\n### " + title + "\n\n") }
	b.WriteString("### " + i18n.R("cve.h.indicators") + "\n\n")
	b.WriteString(indicators(adv))
	h(i18n.R("cve.h.summary"))
	if adv.Summary != "" {
		b.WriteString(adv.Summary + "\n\n")
	}
	bullet := func(label, v string) {
		if v != "" {
			fmt.Fprintf(&b, "- **%s**%s%s\n", label, colon(), v)
		}
	}
	bullet(i18n.R("cve.col.product"), adv.Product)
	if f != nil {
		bullet("CWE", strings.Join(f.CWE, ", "))
		if f.Title != "" && f.Title != adv.Product {
			bullet(i18n.R("cve.l.title"), f.Title)
		}
	}
	bullet(i18n.R("cve.l.prereq"), adv.Exposure)
	if adv.Host {
		bullet(i18n.R("cve.l.scope"), i18n.R("cve.l.host"))
	}
	if f != nil && len(f.Statements) > 0 {
		fmt.Fprintf(&b, "\n**%s**\n", i18n.R("cve.l.statements"))
		for _, st := range f.Statements {
			fmt.Fprintf(&b, "\n> **%s** %s%s%s\n", st.Source, textEvidence(f, st.Source), colon(), st.Text)
		}
	}
	h(i18n.R("cve.h.versions"))
	affected, fixed := i18n.R("cve.col.affected"), i18n.R("cve.col.fixed")
	if adv.Kind == KindCompr {
		affected, fixed = i18n.R("cve.l.malicious"), i18n.R("cve.l.safe")
	}
	bullet(affected, adv.Affected)
	bullet(fixed, adv.Fixed)
	if f != nil {
		for _, r := range f.Upstream {
			bullet(i18n.R("cve.l.upstream"), r.Product+" "+r.Versions)
		}
		b.WriteString(packagesTable(f))
		b.WriteString(fixesTable(f, finds))
	}
	h(i18n.R("cve.h.detection"))
	if adv.Detection != "" {
		b.WriteString(adv.Detection + "\n\n")
	}
	if len(adv.Commands) > 0 {
		b.WriteString("```sh\n" + strings.Join(adv.Commands, "\n") + "\n```\n")
	}
	if len(adv.IOCs) > 0 {
		label := i18n.R("cve.l.traces")
		if adv.Kind == KindCompr {
			label = i18n.R("cve.l.iocs")
		}
		fmt.Fprintf(&b, "\n**%s**\n\n", label)
		for _, x := range adv.IOCs {
			b.WriteString("- " + x + "\n")
		}
	}
	h(i18n.R("cve.h.mitigation"))
	b.WriteString(orDash(adv.Mitigation) + "\n")
	if f != nil {
		for _, m := range f.Mitigations {
			fmt.Fprintf(&b, "\n> **%s** %s%s%s\n", m.Source, textEvidence(f, m.Source), colon(), m.Text)
		}
	}
	h(i18n.R("cve.h.remediation"))
	b.WriteString(orDash(adv.Remediation) + "\n")
	return strings.TrimRight(b.String(), "\n")
}

func colon() string {
	if i18n.Report() == "fr" {
		return " : "
	}
	return ": "
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func textEvidence(f *sources.Facts, label string) string {
	var out []string
	for _, part := range strings.Split(label, sources.SourceSep) {
		if e := evidenceOf(f, sourceName(part)); e != "" && !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return strings.Join(out, "")
}

func sourceName(label string) string {
	switch {
	case strings.HasPrefix(label, "Red Hat"):
		return sources.RedHat
	case strings.HasPrefix(label, "Ubuntu"):
		return sources.Ubuntu
	case strings.HasPrefix(label, "GitHub"):
		return sources.GitHub
	case label == "NVD":
		return sources.NVD
	}
	return sources.CVEOrg
}

func indicators(adv *Advisory) string {
	var b strings.Builder
	f := adv.Facts
	if f == nil {
		if adv.Score != "" {
			fmt.Fprintf(&b, "- **%s**%s%s\n", i18n.R("cve.col.score"), colon(), adv.Score)
		}
		fmt.Fprintf(&b, "- **%s**%s%s\n", i18n.R("cve.l.fiche"), colon(), i18n.R("cve.unofficial"))
		b.WriteString("\n" + legend())
		return b.String()
	}
	type row struct {
		sc   sources.Score
		srcs []string
	}
	var rows []*row
	for _, sc := range f.Scores {
		i := slices.IndexFunc(rows, func(r *row) bool {
			return r.sc.Version == sc.Version && r.sc.Score == sc.Score && r.sc.Vector == sc.Vector
		})
		if i < 0 {
			rows = append(rows, &row{sc: sc})
			i = len(rows) - 1
		}
		if !slices.Contains(rows[i].srcs, sc.Source) {
			rows[i].srcs = append(rows[i].srcs, sc.Source)
		}
	}
	if len(rows) > 0 {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n|---|---|---|---|---|\n", i18n.R("cve.col.score"), i18n.R("cve.col.level"), i18n.R("cve.col.standard"), i18n.R("cve.col.vector"), i18n.R("cve.col.sources"))
		for _, r := range rows {
			fmt.Fprintf(&b, "| **%s** | %s | CVSS %s | %s | %s |\n", decimal(r.sc.Score, 1), severityLabel(r.sc.Severity), r.sc.Version, cell(decodeVector(r.sc.Vector)), cell(strings.Join(r.srcs, ", ")))
		}
		b.WriteString("\n")
	}
	bullet := func(label, v string) {
		if v != "" {
			fmt.Fprintf(&b, "- **%s**%s%s\n", label, colon(), v)
		}
	}
	bullet(i18n.R("cve.l.ratings"), strings.Join(strs(f.Ratings, func(r sources.Rating) string { return r.Source + " " + r.Value }), " · "))
	bullet("CISA KEV", kevLine(f)+" "+evidenceOf(f, sources.KEV))
	if f.SSVC != "" {
		bullet(i18n.R("cve.l.ssvc"), ssvcLine(f.SSVC)+" "+evidenceOf(f, sources.CVEOrg))
	}
	if f.EPSS != nil {
		bullet("EPSS", epssLine(f.EPSS)+" "+evidenceOf(f, sources.EPSS))
	}
	bullet(i18n.R("cve.l.published"), f.Published)
	switch {
	case adv.Cached != "":
		bullet(i18n.R("cve.l.fiche"), i18n.R("cve.cached", adv.Cached))
	case len(adv.Changes) > 0:
		bullet(i18n.R("cve.l.fiche"), i18n.R("cve.changed")+" "+strings.Join(adv.Changes, " ; "))
	}
	var srcs []string
	for _, src := range f.Sources {
		state := ""
		switch src.State {
		case sources.StateAbsent:
			state = " " + i18n.R("cve.src.absent")
		case sources.StateError:
			state = " " + i18n.R("cve.src.error", src.Error)
		}
		ev := ""
		if src.Evidence != "" {
			ev = " [" + src.Evidence + "]"
		}
		srcs = append(srcs, sourceLabel(src.Name)+state+ev)
	}
	bullet(i18n.R("cve.col.sources"), strings.Join(srcs, " · "))
	b.WriteString("\n" + legend())
	return b.String()
}

func legend() string {
	var b strings.Builder
	b.WriteString("> **" + i18n.R("cve.legend") + "**\n")
	for _, k := range []string{"cvss", "vendor", "epss", "kev", "ssvc"} {
		b.WriteString(">\n> " + i18n.R("cve.legend."+k) + "\n")
	}
	return b.String()
}

func packagesTable(f *sources.Facts) string {
	if len(f.Packages) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n| %s | %s | %s | %s |\n|---|---|---|---|\n", i18n.R("cve.col.ecosystem"), i18n.R("cve.col.package"), i18n.R("cve.col.affected"), i18n.R("cve.col.fixed"))
	for _, p := range f.Packages {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", cell(p.Ecosystem), cell(p.Name), cell(p.Vulnerable), cell(orDash(p.Fixed)))
	}
	return b.String()
}

func stateLabel(state string) string {
	if l := i18n.R("cve.fix." + state); !strings.HasPrefix(l, "cve.fix.") {
		return l
	}
	return state
}

var ubuntuReleases = map[string]string{"14.04": "trusty", "16.04": "xenial", "18.04": "bionic", "20.04": "focal", "22.04": "jammy", "24.04": "noble"}

var redhatLike = []string{"rhel", "rocky", "almalinux", "centos", "ol", "oracle"}

func osMatch(osName string, x sources.Fix) bool {
	fields := strings.Fields(strings.ToLower(strings.NewReplacer(`"`, " ", "=", " ").Replace(osName)))
	if len(fields) == 0 {
		return false
	}
	family, version, codename := fields[0], "", ""
	for _, t := range fields[1:] {
		switch {
		case version == "" && t != "" && t[0] >= '0' && t[0] <= '9':
			version = t
		case codename == "":
			codename = t
		}
	}
	major, _, _ := strings.Cut(version, ".")
	switch {
	case slices.Contains(redhatLike, family):
		return x.Distro == sources.RedHat && major != "" && x.Release == "Red Hat Enterprise Linux "+major
	case family == "ubuntu":
		if codename == "" {
			codename = ubuntuReleases[version]
		}
		return x.Distro == sources.Ubuntu && codename != "" && x.Release == codename
	case family == "debian":
		return x.Distro == sources.Debian && major != "" && x.Release == "Debian "+major
	}
	return false
}

func fixesTable(f *sources.Facts, finds []Finding) string {
	if len(f.Fixes) == 0 {
		return ""
	}
	var seen []string
	for _, fd := range finds {
		if fd.OS != "" && !slices.Contains(seen, fd.OS) {
			seen = append(seen, fd.OS)
		}
	}
	rows := f.Fixes
	note := ""
	if len(seen) > 0 {
		rows = slices.DeleteFunc(slices.Clone(f.Fixes), func(x sources.Fix) bool {
			return !slices.ContainsFunc(seen, func(o string) bool { return osMatch(o, x) })
		})
		var ev []string
		for _, name := range sources.Distros {
			if e := evidenceOf(f, name); e != "" {
				ev = append(ev, e)
			}
		}
		note = i18n.R("cve.fixes.filtered", strings.Join(seen, ", "), len(f.Fixes)-len(rows), strings.Join(ev, ""))
	}
	var b strings.Builder
	b.WriteString("\n**" + i18n.R("cve.l.distros") + "**")
	if note != "" {
		b.WriteString(" — " + note)
	}
	b.WriteString("\n\n")
	if len(rows) == 0 {
		return b.String()
	}
	fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n|---|---|---|---|---|---|\n", i18n.R("cve.col.distro"), i18n.R("cve.col.release"), i18n.R("cve.col.package"), i18n.R("cve.col.state"), i18n.R("cve.col.fixed_version"), i18n.R("cve.col.advisory"))
	for _, x := range rows {
		v := x.Version
		if v == "" {
			v = x.Note
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", sourceLabel(x.Distro), cell(x.Release), cell(x.Package), stateLabel(x.State), cell(orDash(v)), cell(orDash(x.Advisory)))
	}
	return b.String()
}

func fixFor(f *sources.Facts, fd Finding) string {
	if f == nil || fd.OS == "" {
		return ""
	}
	var parts []string
	var pkgs []string
	for _, x := range f.Fixes {
		if osMatch(fd.OS, x) && !slices.Contains(pkgs, x.Package) {
			pkgs = append(pkgs, x.Package)
		}
	}
	for _, x := range f.Fixes {
		if !osMatch(fd.OS, x) {
			continue
		}
		s := stateLabel(x.State)
		if x.Version != "" {
			s = x.Version
		}
		if x.Advisory != "" {
			s += " (" + x.Advisory + ")"
		}
		if len(pkgs) > 1 {
			s = x.Package + " " + s
		}
		if !slices.Contains(parts, s) {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ; ")
}

func shortCmd(s string) string {
	s = oneLine(s)
	return "`" + strings.ReplaceAll(shorten(s, maxTestLen), "`", "'") + "`"
}

type check struct {
	cmd, id string
}

func (s *Store) checks(fd Finding) []check {
	var out []check
	for _, id := range fd.Evidence {
		it, ok := s.ev.Item(id)
		if !ok || it.Error != "" || it.Tool == "" || !checking(it.Tool) || it.Tool == sources.ToolName {
			continue
		}
		c := shortCmd(command(it.Tool, it.Args))
		if !slices.ContainsFunc(out, func(x check) bool { return x.cmd == c }) {
			out = append(out, check{c, id})
		}
	}
	return out
}

func (s *Store) tests(fd Finding) []string {
	return strs(s.checks(fd), func(c check) string { return c.cmd })
}

func (c check) String() string { return c.cmd + " " + c.id }

func command(tool, args string) string {
	var m map[string]any
	if json.Unmarshal([]byte(args), &m) != nil {
		return tool + " " + args
	}
	words := func(v any) []string {
		list, ok := v.([]any)
		if !ok {
			return nil
		}
		var out []string
		for _, x := range list {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	for _, k := range []string{"argv", "command", "cmd"} {
		switch v := m[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case []any:
			if argv := words(v); len(argv) > 0 {
				if script, ok := access.ShellScript(argv); ok {
					return script
				}
				return access.Display(argv)
			}
		}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		if k != "host" && k != "target" {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	parts := []string{tool}
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			if v != "" {
				parts = append(parts, v)
			}
		case float64:
			parts = append(parts, k+"="+strconv.FormatFloat(v, 'f', -1, 64))
		case bool:
			if v {
				parts = append(parts, k)
			}
		case []any:
			parts = append(parts, words(v)...)
		}
	}
	return strings.Join(parts, " ")
}

func verdict(finds []Finding) string {
	counts := map[string]int{}
	exp := map[string]int{}
	for _, f := range finds {
		counts[f.Status]++
		if f.Status == Vulnerable || f.Status == Compromised {
			exp[f.Exposure]++
		}
	}
	var b strings.Builder
	if counts[Compromised] > 0 {
		fmt.Fprintf(&b, "☠️ %d %s · ", counts[Compromised], i18n.R("cve.st.compromised"))
	}
	fmt.Fprintf(&b, "🚨 %d %s · ❓ %d %s · ✅ %d %s (%d %s)", counts[Vulnerable], i18n.R("cve.st.vulnerable"), counts[Unknown], i18n.R("cve.st.unknown"), counts[Clean], i18n.R("cve.st.clean"), len(finds), i18n.R("cve.assets"))
	if pos := counts[Vulnerable] + counts[Compromised]; pos > 0 {
		var parts []string
		for _, e := range exposures {
			if exp[e] > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", exp[e], i18n.R("cve.exp."+e)))
			}
		}
		if exp[""] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", exp[""], i18n.R("cve.exp.unmeasured")))
		}
		fmt.Fprintf(&b, "\n\n%s%s%s", i18n.R("cve.l.positives_exposure"), colon(), strings.Join(parts, " · "))
	}
	if len(finds) == 0 {
		return i18n.R("cve.no_assets")
	}
	return b.String()
}

func exposureRank(e string) int {
	switch e {
	case Exposed:
		return 0
	case Unmeasured, "":
		return 1
	}
	return 2
}

func (s *Store) positives(adv *Advisory, finds []Finding) string {
	var rows []Finding
	for _, f := range finds {
		if f.Status == Vulnerable || f.Status == Compromised {
			rows = append(rows, f)
		}
	}
	if len(rows) == 0 {
		return i18n.R("cve.none_positive")
	}
	slices.SortStableFunc(rows, func(a, b Finding) int {
		if a.Status != b.Status {
			if a.Status == Compromised {
				return -1
			}
			return 1
		}
		if d := exposureRank(a.Exposure) - exposureRank(b.Exposure); d != 0 {
			return d
		}
		return strings.Compare(a.Asset, b.Asset)
	})
	var facts *sources.Facts
	if adv != nil {
		facts = adv.Facts
	}
	var b strings.Builder
	if len(rows) > 1 {
		fmt.Fprintf(&b, "| | %s | %s | %s |\n|---|---|---|---|\n", i18n.R("cve.col.asset"), i18n.R("cve.col.exposure"), i18n.R("cve.col.fixed_in"))
		for _, f := range rows {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", Icon(f.Status), cell(f.Asset), exposureLabel(f), cell(orDash(fixFor(facts, f))))
		}
		b.WriteString("\n")
	}
	for _, f := range rows {
		s.assetCard(&b, f, facts)
	}
	return strings.TrimRight(b.String(), "\n")
}

func exposureLabel(f Finding) string {
	if f.Exposure == "" {
		return "—"
	}
	return i18n.R("cve.exp1." + f.Exposure)
}

func (s *Store) assetCard(b *strings.Builder, f Finding, facts *sources.Facts) {
	head := typeLabel(f.Type, 1)
	if f.OS != "" {
		head += ", " + f.OS
	}
	fmt.Fprintf(b, "**%s %s** (%s)\n\n", Icon(f.Status), f.Asset, head)
	bullet := func(label, v string) {
		if v != "" {
			fmt.Fprintf(b, "- **%s**%s%s\n", label, colon(), v)
		}
	}
	found := i18n.R("cve.col.found")
	if f.Status == Unknown {
		found = i18n.R("cve.col.missing")
	}
	bullet(found, f.withHosts())
	bullet(i18n.R("cve.col.fixed_in"), fixFor(facts, f))
	if f.Exposure != "" {
		bullet(i18n.R("cve.col.exposure"), "**"+exposureLabel(f)+"**"+colon()+f.Conditions)
	}
	checks := s.checks(f)
	if len(checks) > 0 {
		bullet(i18n.R("cve.col.test"), checks[0].String())
	}
	if len(checks) > 1 {
		rest := checks[1:]
		more := ""
		if len(rest) > maxTests {
			more = fmt.Sprintf(" +%d", len(rest)-maxTests)
			rest = rest[:maxTests]
		}
		bullet(i18n.R("cve.l.other_checks"), strings.Join(strs(rest, check.String), " ; ")+more)
	}
	bullet(i18n.R("cve.col.evidence"), strings.Join(f.Evidence, ""))
	b.WriteString("\n")
}

func typeLabel(t string, n int) string {
	if t == "" {
		t = "other"
	}
	if n > 1 {
		return i18n.R("cve.type." + t + ".pl")
	}
	return i18n.R("cve.type." + t)
}

func (s *Store) unknowns(finds []Finding) string {
	var rows []Finding
	for _, f := range finds {
		if f.Status == Unknown {
			rows = append(rows, f)
		}
	}
	if len(rows) == 0 {
		return i18n.R("cve.none_unknown")
	}
	slices.SortStableFunc(rows, func(a, b Finding) int { return strings.Compare(a.Asset, b.Asset) })
	var b strings.Builder
	for _, f := range rows {
		s.assetCard(&b, f, nil)
	}
	return strings.TrimRight(b.String(), "\n")
}

func (s *Store) negatives(finds []Finding) string {
	var clean []Finding
	for _, f := range finds {
		if f.Status == Clean {
			clean = append(clean, f)
		}
	}
	if len(clean) == 0 {
		return i18n.R("cve.none_clean")
	}
	slices.SortStableFunc(clean, func(a, b Finding) int { return strings.Compare(a.Asset, b.Asset) })
	var b strings.Builder
	for _, t := range append(slices.Clone(assetTypes), "") {
		var mine []Finding
		for _, f := range clean {
			if f.Type == t || t == "" && !slices.Contains(assetTypes, f.Type) {
				mine = append(mine, f)
			}
		}
		if len(mine) == 0 {
			continue
		}
		fmt.Fprintf(&b, "**%s** (%d)\n\n", typeLabel(t, 2), len(mine))
		var groups []string
		members := map[string][]string{}
		tests := map[string][]string{}
		proofs := map[string][]string{}
		for _, f := range mine {
			g, leaf := splitAsset(f.Asset)
			if _, ok := members[g]; !ok {
				groups = append(groups, g)
			}
			members[g] = append(members[g], leaf)
			for _, c := range s.tests(f) {
				if !slices.Contains(tests[g], c) {
					tests[g] = append(tests[g], c)
				}
			}
			for _, e := range f.Evidence {
				if !slices.Contains(proofs[g], e) {
					proofs[g] = append(proofs[g], e)
				}
			}
		}
		for _, g := range groups {
			name := g
			if name == "" {
				name = "—"
			}
			fmt.Fprintf(&b, "- `%s` (%d)%s%s", name, len(members[g]), colon(), strings.Join(members[g], ", "))
			if t := tests[g]; len(t) > 0 {
				more := ""
				if len(t) > maxTests {
					more = fmt.Sprintf(" +%d", len(t)-maxTests)
					t = t[:maxTests]
				}
				fmt.Fprintf(&b, " — %s%s%s%s", i18n.R("cve.l.tests"), colon(), strings.Join(t, " ; "), more)
			}
			if p := proofs[g]; len(p) > 0 {
				more := ""
				if len(p) > maxProofs {
					more = fmt.Sprintf(" +%d", len(p)-maxProofs)
					p = p[:maxProofs]
				}
				b.WriteString(" " + strings.Join(p, "") + more)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
