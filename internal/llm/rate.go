package llm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/filelock"
)

const rateWindow = time.Minute + time.Second

var rateDir = func() string { return filepath.Join(config.StateDir(), "clotr", "rate") }

type rateGate struct {
	mu    sync.Mutex
	limit int
	sent  []time.Time
	until time.Time
	file  *os.File
	now   func() time.Time
	after func(time.Duration) <-chan time.Time
}

type rateState struct {
	Sent  []time.Time `json:"sent"`
	Until time.Time   `json:"until"`
}

func newRateGate(limit int) *rateGate {
	return &rateGate{limit: limit, now: time.Now, after: time.After}
}

var unsafeRateName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func newSharedRateGate(limit int, provider string) *rateGate {
	g := newRateGate(limit)
	if f, err := filelock.Open(filepath.Join(rateDir(), unsafeRateName.ReplaceAllString(provider, "_")+".json")); err == nil {
		g.file = f
	}
	return g
}

func (g *rateGate) shared(fn func()) {
	if g.file == nil || filelock.Lock(g.file) != nil {
		fn()
		return
	}
	defer func() { _ = filelock.Unlock(g.file) }()
	if data, err := filelock.ReadLocked(g.file); err == nil {
		var st rateState
		if json.Unmarshal(data, &st) != nil {
			st = rateState{}
		}
		g.sent, g.until = st.Sent, st.Until
	}
	fn()
	if data, err := json.Marshal(rateState{Sent: g.sent, Until: g.until}); err == nil {
		_ = filelock.WriteLocked(g.file, data)
	}
}

func (g *rateGate) delay() time.Duration {
	now := g.now()
	if now.Before(g.until) {
		return g.until.Sub(now)
	}
	if g.limit <= 0 {
		return 0
	}
	cut := now.Add(-rateWindow)
	i := 0
	for i < len(g.sent) && !g.sent[i].After(cut) {
		i++
	}
	g.sent = g.sent[i:]
	if len(g.sent) < g.limit {
		g.sent = append(g.sent, now)
		return 0
	}
	return g.sent[0].Add(rateWindow).Sub(now)
}

func (g *rateGate) wait(ctx context.Context) error {
	for {
		var d time.Duration
		g.mu.Lock()
		g.shared(func() { d = g.delay() })
		g.mu.Unlock()
		if d <= 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-g.after(d):
		}
	}
}

func (g *rateGate) block(d time.Duration) {
	if d <= 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.shared(func() {
		if until := g.now().Add(min(d, rateWindow)); until.After(g.until) {
			g.until = until
		}
	})
}

var limitResets = regexp.MustCompile(`[Ll]imit resets at:? (\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}) UTC`)

func parseLimitReset(body string, now time.Time) time.Duration {
	m := limitResets.FindStringSubmatch(body)
	if m == nil {
		return 0
	}
	t, err := time.Parse("2006-01-02 15:04:05", m[1][:10]+" "+m[1][11:])
	if err != nil {
		return 0
	}
	if d := t.Sub(now); d > 0 {
		return d
	}
	return 0
}
