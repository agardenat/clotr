package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agardenat/clotr/internal/config"
)

type fakeClock struct {
	t     time.Time
	waits []time.Duration
}

func (f *fakeClock) now() time.Time { return f.t }

func (f *fakeClock) after(d time.Duration) <-chan time.Time {
	f.waits = append(f.waits, d)
	f.t = f.t.Add(d)
	ch := make(chan time.Time, 1)
	ch <- f.t
	return ch
}

func gateWithClock(limit int) (*rateGate, *fakeClock) {
	c := &fakeClock{t: time.Date(2026, 11, 17, 14, 0, 0, 0, time.UTC)}
	g := newRateGate(limit)
	g.now, g.after = c.now, c.after
	return g, c
}

func TestRateGateSlidingWindow(t *testing.T) {
	g, c := gateWithClock(3)
	ctx := context.Background()
	for range 3 {
		if err := g.wait(ctx); err != nil {
			t.Fatal(err)
		}
		c.t = c.t.Add(10 * time.Second)
	}
	if len(c.waits) != 0 {
		t.Fatalf("aucune attente sous la limite : %v", c.waits)
	}
	if err := g.wait(ctx); err != nil {
		t.Fatal(err)
	}
	if len(c.waits) != 1 || c.waits[0] != rateWindow-30*time.Second {
		t.Fatalf("4e appel : attendre la sortie du 1er de la fenêtre, attentes %v", c.waits)
	}
	start := c.t.Add(-rateWindow)
	n := 0
	for _, s := range g.sent {
		if s.After(start) {
			n++
		}
	}
	if n > 3 {
		t.Fatalf("%d envois dans la fenêtre", n)
	}
}

func TestRateGateBlockShared(t *testing.T) {
	g, c := gateWithClock(0)
	g.block(20 * time.Second)
	if err := g.wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.waits) != 1 || c.waits[0] != 20*time.Second {
		t.Fatalf("attentes %v", c.waits)
	}
	g.block(time.Hour)
	if d := g.until.Sub(c.t); d != rateWindow {
		t.Fatalf("pause plafonnée à la fenêtre, obtenu %s", d)
	}
}

func TestRateGateCancel(t *testing.T) {
	g := newRateGate(0)
	g.block(time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := g.wait(ctx); err == nil {
		t.Fatal("annulation attendue")
	}
}

func TestParseLimitReset(t *testing.T) {
	now := time.Date(2026, 11, 17, 14, 21, 0, 0, time.UTC)
	body := `{"error":{"message":"Rate limit exceeded for api_key: abc. Limit type: requests. Current limit: 30, Remaining: 0. Limit resets at: 2026-11-17 14:21:27 UTC","code":"429"}}`
	if d := parseLimitReset(body, now); d != 27*time.Second {
		t.Fatalf("obtenu %s", d)
	}
	if d := parseLimitReset(body, now.Add(time.Minute)); d != 0 {
		t.Fatalf("reprise passée : %s", d)
	}
	if d := parseLimitReset("rate limited", now); d != 0 {
		t.Fatalf("sans date : %s", d)
	}
}

func TestPool429BlocksProvider(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	no := false
	cfg := &config.Config{Providers: []config.Provider{{Name: "p", BaseURL: srv.URL, MaxConcurrency: 4, Stream: &no}}}
	p := NewPool(cfg, srv.Client())
	if _, err := p.Chat(context.Background(), "p", Request{Model: "m"}); RetryAfter(err) != time.Second {
		t.Fatalf("429 attendu avec Retry-After : %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := p.Chat(ctx, "p", Request{Model: "m"}); err == nil || ctx.Err() == nil {
		t.Fatalf("appel suivant retenu pendant la pause : %v", err)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("%d requêtes envoyées pendant la pause", n)
	}
}
