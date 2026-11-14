package main

import (
	"time"

	"github.com/agardenat/clotr/internal/agent"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/tools"
)

func (rt *app) newRunner(events progress.Sink, reg *tools.Registry) *agent.Runner {
	r := &agent.Runner{
		Chat:            rt.pool,
		Tools:           reg,
		Audit:           rt.audit,
		Events:          events,
		MaxSteps:        rt.cfg.Limits.MaxSteps,
		ConcludeReserve: min(5*time.Minute, rt.cfg.Limits.RequestTimeout.Duration),
		Attempts:        2,
		Backoff:         2 * time.Second,
		RoundPause:      30 * time.Second,
		Persistent: func(provider string) bool {
			p, ok := rt.cfg.Provider(provider)
			return ok && p.PersistentRetry
		},
		StallSteps: *rt.cfg.Limits.StallSteps,
		KeepSteps:  *rt.cfg.Limits.HistoryKeepSteps,
		ToolChars:  *rt.cfg.Limits.HistoryToolChars,
		Budget:     rt.budget,
	}
	if rt.memory != nil {
		r.ConcludeNotes = rt.memory.TaskNotes
	}
	return r
}
