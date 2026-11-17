package httpx

import (
	"strings"
	"testing"
)

func TestSnippet(t *testing.T) {
	if got := Snippet([]byte("<html>\n<head><title>404 Not Found</title></head>\n</html>"), 0); got != "page HTML: 404 Not Found" {
		t.Errorf("%q", got)
	}
	if got := Snippet([]byte(" {\"error\":\n \"x\"} "), 0); got != `{"error": "x"}` {
		t.Errorf("%q", got)
	}
	if got := Snippet([]byte("abcdef"), 3); got != "abc…" {
		t.Errorf("%q", got)
	}
}

func TestSnippetShortensKeys(t *testing.T) {
	key := strings.Repeat("ab12", 16)
	got := Snippet([]byte(`{"message":"Rate limit exceeded for api_key: `+key+`. Limit type: requests","id":"123e4567-e89b-12d3-a456-426614174000","k":"sk-`+key+`"}`), 500)
	if strings.Contains(got, key) {
		t.Fatalf("clé complète dans %q", got)
	}
	for _, want := range []string{"api_key: ab12…ab12.", "sk-ab12…ab12", "123e4567-e89b-12d3-a456-426614174000"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q absent de %q", want, got)
		}
	}
}
