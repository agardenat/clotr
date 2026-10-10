package template

import (
	"strings"
	"testing"
	"time"
)

func TestLogStats(t *testing.T) {
	var b strings.Builder
	b.WriteString("partial line cut by tail\n")
	for i := 0; i < 90; i++ {
		ts := time.Date(2026, 10, 8, 14, i%60, 0, 0, time.UTC).Add(time.Duration(i/60) * time.Hour)
		b.WriteString(ts.Format("2006-01-02 15:04:05") + ",123 [pool-" + string(rune('0'+i%7)) + "] INFO  org.example.app.RequestHandler - authorized request id=" + strings.Repeat("9", i%5+1) + " from 10.0.0." + string(rune('1'+i%3)) + "\n")
	}
	for i := 0; i < 10; i++ {
		b.WriteString("2026-10-08 15:30:00,000 [main] ERROR org.example.app.Writer - destination unreachable password=hunter2\n")
	}
	out := LogStats(b.String(), 50<<20, time.Unix(0, 0), b.Len(), true, 5)
	for _, want := range []string{"INFO=90", "ERROR=10", "org.example.app.RequestHandler", "90.0 %", "authorized request id=# from <ip>", "lignes par heure: 2026-10-08 14h=60 2026-10-08 15h=40", "taille du fichier: 50.0 Mio"} {
		if !strings.Contains(out, want) {
			t.Errorf("absent %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "hunter2") || strings.Contains(out, "partial line") {
		t.Errorf("fuite ou ligne tronquée comptée:\n%s", out)
	}
}

func TestLogStatsHTTPCodes(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 8; i++ {
		b.WriteString(`10.0.0.1 - - [08/Oct/2026:18:00:0` + string(rune('0'+i)) + ` +0000] "POST /api/authz/adls/access HTTP/1.1" 200 558 ["1 ms"]` + "\n")
	}
	b.WriteString(`10.0.0.1 - - [08/Oct/2026:18:00:09 +0000] "POST /api/authz/adls/access HTTP/1.1" 401 0 ["0 ms"]` + "\n")
	b.WriteString(`10.0.0.1 - - [08/Oct/2026:18:00:09 +0000] "GET / HTTP/1.1" 401 0 ["0 ms"]` + "\n")
	out := LogStats(b.String(), int64(b.Len()), time.Unix(0, 0), b.Len(), false, 5)
	for _, want := range []string{"codes HTTP: 200=8 (80.0 %) 401=2 (20.0 %)", `"POST /api/authz/adls/access HTTP/#.#" 200`, `"POST /api/authz/adls/access HTTP/#.#" 401`} {
		if !strings.Contains(out, want) {
			t.Errorf("absent %q:\n%s", want, out)
		}
	}
}
