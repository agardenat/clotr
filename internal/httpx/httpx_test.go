package httpx

import "testing"

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
