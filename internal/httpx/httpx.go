package httpx

import (
	"regexp"
	"strings"
)

var UserAgent = "clotr/dev"

var (
	spaces = regexp.MustCompile(`\s+`)
	title  = regexp.MustCompile(`(?is)<title>(.*?)</title>`)
)

func Snippet(body []byte, max int) string {
	s := strings.TrimSpace(string(body))
	if strings.HasPrefix(s, "<") {
		if m := title.FindStringSubmatch(s); m != nil {
			s = "page HTML: " + strings.TrimSpace(m[1])
		} else {
			s = "page HTML"
		}
	}
	s = spaces.ReplaceAllString(s, " ")
	if max > 0 && len(s) > max {
		s = s[:max] + "…"
	}
	return s
}
