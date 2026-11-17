package llm

import (
	"context"
	"regexp"
	"sync"
	"time"
)

const rateWindow = time.Minute + time.Second

type rateGate struct {
	mu    sync.Mutex
	limit int
	sent  []time.Time
	until time.Time
	now   func() time.Time
	after func(time.Duration) <-chan time.Time
}

func newRateGate(limit int) *rateGate {
	return &rateGate{limit: limit, now: time.Now, after: time.After}
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
		g.mu.Lock()
		d := g.delay()
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
	if until := g.now().Add(min(d, rateWindow)); until.After(g.until) {
		g.until = until
	}
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
