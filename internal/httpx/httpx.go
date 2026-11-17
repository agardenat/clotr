package httpx

import (
	"regexp"
	"strings"
)

var UserAgent = "clotr/dev"

var (
	spaces = regexp.MustCompile(`\s+`)
	title  = regexp.MustCompile(`(?is)<title>(.*?)</title>`)
	token  = regexp.MustCompile(`[A-Za-z0-9_]{32,}`)
)

func Shorten(s string) string {
	return token.ReplaceAllStringFunc(s, func(t string) string { return t[:4] + "…" + t[len(t)-4:] })
}

func Snippet(body []byte, max int) string {
	s := strings.TrimSpace(string(body))
	if strings.HasPrefix(s, "<") {
		if m := title.FindStringSubmatch(s); m != nil {
			s = "page HTML: " + strings.TrimSpace(m[1])
		} else {
			s = "page HTML"
		}
	}
	s = Shorten(spaces.ReplaceAllString(s, " "))
	if max > 0 && len(s) > max {
		s = s[:max] + "…"
	}
	return s
}
