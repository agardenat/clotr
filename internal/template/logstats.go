package template

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/driver/ssh"
)

var (
	tsRe      = regexp.MustCompile(`(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})`)
	accessTS  = regexp.MustCompile(`\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})`)
	levelRe   = regexp.MustCompile(`\b(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|SEVERE)\b`)
	loggerRe  = regexp.MustCompile(`^[\[(]?([A-Za-z_][\w$]*(?:\.[\w$]+){2,})[\])]?:?$`)
	prefixRe  = regexp.MustCompile(`^\s*(\[?\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}([.,]\d+)?\]?|\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})`)
	uuidRe    = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	hexRe     = regexp.MustCompile(`\b(0x)?[0-9a-fA-F]{10,}\b`)
	numRe     = regexp.MustCompile(`\d+`)
	ipRe      = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`)
	spacesRe  = regexp.MustCompile(`\s+`)
	threadRe  = regexp.MustCompile(`\[[^\]]{0,80}\]`)
	httpRe    = regexp.MustCompile(`"[A-Z]+ [^"]*HTTP/[\d.]+" (\d{3}) `)
	accessTZ  = "02/Jan/2006:15:04:05"
	isoLayout = "2006-01-02 15:04:05"
)

type count struct {
	key string
	n   int
}

func top(m map[string]int, n int) []count {
	out := make([]count, 0, len(m))
	for k, v := range m {
		out = append(out, count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].key < out[j].key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func normalize(line string) string {
	l := prefixRe.ReplaceAllString(line, "")
	l = threadRe.ReplaceAllString(l, "[…]")
	l = uuidRe.ReplaceAllString(l, "<uuid>")
	l = ipRe.ReplaceAllString(l, "<ip>")
	l = hexRe.ReplaceAllString(l, "<hex>")
	l = numRe.ReplaceAllString(l, "#")
	l = strings.TrimSpace(spacesRe.ReplaceAllString(l, " "))
	if len(l) > 180 {
		l = l[:180] + "…"
	}
	return l
}

func parseTime(line string) (time.Time, bool) {
	if m := tsRe.FindStringSubmatch(line); m != nil {
		t, err := time.Parse(isoLayout, m[1]+" "+m[2])
		return t, err == nil
	}
	if m := accessTS.FindStringSubmatch(line); m != nil {
		t, err := time.Parse(accessTZ, m[1])
		return t, err == nil
	}
	return time.Time{}, false
}

func LogStats(raw string, fileSize int64, mtime time.Time, sampled int, truncated bool, topN int) string {
	lines := strings.Split(raw, "\n")
	if truncated && len(lines) > 1 {
		lines = lines[1:]
	}
	levels := map[string]int{}
	codes := map[string]int{}
	loggers := map[string]int{}
	patterns := map[string]int{}
	perHour := map[string]int{}
	var first, last time.Time
	n := 0
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		n++
		if t, ok := parseTime(l); ok {
			if first.IsZero() || t.Before(first) {
				first = t
			}
			if t.After(last) {
				last = t
			}
			perHour[t.Format("2006-01-02 15h")]++
		}
		lvl := ""
		if loc := levelRe.FindStringIndex(l); loc != nil && loc[0] < 120 {
			lvl = l[loc[0]:loc[1]]
			levels[lvl]++
			for i, tok := range strings.Fields(l[loc[1]:]) {
				if i > 2 {
					break
				}
				if m := loggerRe.FindStringSubmatch(tok); m != nil {
					loggers[m[1]]++
					break
				}
			}
		}
		key := normalize(l)
		if m := httpRe.FindStringSubmatch(l); m != nil {
			codes[m[1]]++
			key = strings.Replace(key, "\" # ", "\" "+m[1]+" ", 1)
		}
		patterns[key]++
	}
	var b strings.Builder
	fmt.Fprintf(&b, "taille du fichier: %s ; modifié: %s\n", human(fileSize), mtime.UTC().Format(time.RFC3339))
	cover := "fichier entier"
	if truncated {
		cover = fmt.Sprintf("derniers %s (%.0f %% du fichier)", human(int64(sampled)), 100*float64(sampled)/float64(max(fileSize, 1)))
	}
	fmt.Fprintf(&b, "échantillon: %s, %d lignes\n", cover, n)
	if !first.IsZero() && last.After(first) {
		span := last.Sub(first)
		rate := float64(n) / span.Hours()
		bytesRate := float64(sampled) / span.Hours()
		fmt.Fprintf(&b, "période de l'échantillon: %s → %s (%s) ; débit moyen sur cette période: %.0f lignes/h, %s/h (ne pas extrapoler à la journée : voir lignes par heure)\n", first.Format(isoLayout), last.Format(isoLayout), span.Truncate(time.Second), rate, human(int64(bytesRate)))
	}
	if len(levels) > 0 {
		var parts []string
		for _, c := range top(levels, 10) {
			parts = append(parts, fmt.Sprintf("%s=%d", c.key, c.n))
		}
		fmt.Fprintf(&b, "niveaux: %s\n", strings.Join(parts, " "))
	}
	if len(codes) > 0 {
		var parts []string
		for _, c := range top(codes, 15) {
			parts = append(parts, fmt.Sprintf("%s=%d (%.1f %%)", c.key, c.n, 100*float64(c.n)/float64(max(n, 1))))
		}
		fmt.Fprintf(&b, "codes HTTP: %s\n", strings.Join(parts, " "))
	}
	if len(perHour) > 1 {
		keys := make([]string, 0, len(perHour))
		for k := range perHour {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > 24 {
			keys = keys[len(keys)-24:]
		}
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", k, perHour[k]))
		}
		fmt.Fprintf(&b, "lignes par heure: %s\n", strings.Join(parts, " "))
	}
	if len(loggers) > 0 {
		b.WriteString("loggers les plus bavards:\n")
		for _, c := range top(loggers, topN) {
			fmt.Fprintf(&b, "  %6d  %5.1f %%  %s\n", c.n, 100*float64(c.n)/float64(max(n, 1)), c.key)
		}
	}
	b.WriteString("messages les plus répétés (chiffres → #):\n")
	for _, c := range top(patterns, topN) {
		fmt.Fprintf(&b, "  %6d  %5.1f %%  %s\n", c.n, 100*float64(c.n)/float64(max(n, 1)), c.key)
	}
	return ssh.Redact(b.String())
}

func human(n int64) string {
	f := float64(n)
	for _, u := range []string{"o", "Kio", "Mio", "Gio"} {
		if f < 1024 {
			if u == "o" {
				return strconv.FormatInt(int64(f), 10) + " o"
			}
			return fmt.Sprintf("%.1f %s", f, u)
		}
		f /= 1024
	}
	return fmt.Sprintf("%.1f Tio", f)
}
