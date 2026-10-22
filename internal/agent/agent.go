package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/agardenat/clotr/internal/audit"
	"github.com/agardenat/clotr/internal/budget"
	"github.com/agardenat/clotr/internal/catalog"
	"github.com/agardenat/clotr/internal/evidence"
	"github.com/agardenat/clotr/internal/i18n"
	"github.com/agardenat/clotr/internal/lead"
	"github.com/agardenat/clotr/internal/llm"
	"github.com/agardenat/clotr/internal/progress"
	"github.com/agardenat/clotr/internal/tools"
)

var (
	thinkBlock = regexp.MustCompile(`(?s)<think>.*?</think>`)
	leakedCall = regexp.MustCompile(`to=functions\.([A-Za-z0-9_.\-]+)`)
)

const (
	concludeMsg      = "Limite d'étapes atteinte. Conclus maintenant avec les éléments déjà collectés, au format demandé, sans appeler d'outil. Indique dans gaps ce qui reste à faire."
	concludeStallMsg = "Tes derniers appels n'apportent plus rien de nouveau (mêmes outils, mêmes paramètres). Conclus maintenant avec les éléments collectés, au format demandé, sans appeler d'outil. Indique dans gaps ce qui reste à faire et pourquoi tu n'as pas pu avancer."
	emptyMsg         = "Ta réponse ne contient aucun texte (seulement un raisonnement). Écris maintenant la réponse finale au format demandé, sans appeler d'outil."
	continueMsg      = "Ta réponse a été coupée par la limite de longueur. Continue exactement là où elle s'arrête, sans rien répéter ni ajouter de préambule."
	concludeTimeMsg  = "Temps presque écoulé. Conclus maintenant avec les éléments déjà collectés, au format demandé, sans appeler d'outil. Indique dans gaps ce qui reste à faire."
	concludeNowMsg   = "L'utilisateur demande de conclure maintenant. Conclus avec les éléments déjà collectés, au format demandé, sans appeler d'outil. Indique dans gaps ce qui reste à faire."
	inboxMsg         = "Causes signalées par d'autres tâches pendant que tu travailles (preuves citées, non vérifiées par toi) :\n%s\nNe refais pas leur collecte. Si ta tâche est concernée, vérifie-les ou cherche le correctif ; sinon poursuis ta tâche."
)

const (
	maxChecks       = 2
	maxEmptyRetries = 2
	maxResumes      = 3
	maxRoundPause   = 5 * time.Minute
	maxOutputTokens = 32000
)

type Runner struct {
	ConcludeReserve time.Duration
	RoundPause      time.Duration
	Persistent      func(provider string) bool
	KeepSteps       int
	ToolChars       int
	StallSteps      int
	ConcludeNotes   func(task string) string
	Inbox           func(reader tools.Caller) string
	InboxFormat     string
	Evidence        *evidence.Store
	Journal         bool
	Chat            llm.Chatter
	Tools           *tools.Registry
	Audit           *audit.Logger
	Events          progress.Sink
	MaxSteps        int
	Attempts        int
	Backoff         time.Duration
	Budget          *budget.Tracker
	Boundary        Boundary
	down            sync.Map
	concluding      atomic.Bool
}

func (r *Runner) ConcludeNow() { r.concluding.Store(true) }

func (r *Runner) Concluding() bool { return r.concluding.Load() }

type Boundary interface {
	Outbound(model catalog.ModelInfo, msgs []llm.Message) []llm.Message
	Inbound(model catalog.ModelInfo, msg llm.Message) llm.Message
}

type Passthrough struct{}

func (Passthrough) Outbound(_ catalog.ModelInfo, msgs []llm.Message) []llm.Message { return msgs }
func (Passthrough) Inbound(_ catalog.ModelInfo, msg llm.Message) llm.Message       { return msg }

func (r *Runner) boundary() Boundary {
	if r.Boundary == nil {
		return Passthrough{}
	}
	return r.Boundary
}

type Spec struct {
	TaskID     string
	Role       string
	System     string
	User       string
	Tools      []string
	Candidates []catalog.ModelInfo
	Deadline   time.Time
	Check      func(content string) string
	OnText     func(text string)
	Reached    func() string
}

type Output struct {
	Content   string
	Model     string
	Steps     int
	ToolCalls int
	Usage     llm.Usage
	Cost      float64
	Sovereign bool
	Limited   bool
	Limit     string
}

func (r *Runner) unavailable(m catalog.ModelInfo) string {
	if reason := r.Budget.Exhausted(m.Provider); reason != "" {
		return "budget " + m.Provider + ": " + reason
	}
	if _, down := r.down.Load(m.Ref()); down {
		return i18n.T("agent.down")
	}
	return ""
}

func (r *Runner) First(cands []catalog.ModelInfo) string {
	for _, c := range cands {
		if r.unavailable(c) == "" {
			return c.Ref()
		}
	}
	return i18n.T("agent.none")
}

type session struct {
	id    string
	r     *Runner
	spec  Spec
	cur   int
	out   *Output
	model catalog.ModelInfo
	shown string
}

func (r *Runner) Run(ctx context.Context, spec Spec) (*Output, error) {
	if len(spec.Candidates) == 0 {
		return nil, i18n.E("agent.no_candidate", spec.TaskID)
	}
	s := &session{r: r, spec: spec, out: &Output{}, id: newSessionID()}
	msgs := []llm.Message{{Role: "system", Content: spec.System}, {Role: "user", Content: spec.User}}
	defs := r.Tools.Defs(spec.Tools)
	maxSteps := max(r.MaxSteps, 1)
	var lastStep time.Duration
	var produced []toolMsg
	seen := map[string]bool{}
	idle, checks := 0, 0
	reached := ""
	for step := 1; ; step++ {
		s.out.Steps = step
		t0 := time.Now()
		late := !spec.Deadline.IsZero() && len(defs) > 0 && step > 1 && time.Until(spec.Deadline) < lastStep
		stalled := r.StallSteps > 0 && idle >= r.StallSteps && len(defs) > 0
		interrupted := r.Concluding() && len(defs) > 0
		final := step > maxSteps || late || stalled || interrupted || reached != "" || len(defs) == 0
		switch {
		case reached != "" && !interrupted:
			msgs = append(msgs, llm.Message{Role: "user", Content: reached + r.notes(spec.TaskID)})
			r.Audit.Log("goal_reached", map[string]any{"task": spec.TaskID, "step": step})
		case interrupted:
			s.out.Limited, s.out.Limit = true, "interrupted"
			msgs = append(msgs, llm.Message{Role: "user", Content: concludeNowMsg + r.notes(spec.TaskID)})
			r.Audit.Log("conclude_now", map[string]any{"task": spec.TaskID, "step": step})
			r.Events.Emit(progress.Event{Task: spec.TaskID, Kind: "interrupted", Detail: i18n.T("limit.user"), Step: step})
		case stalled:
			s.out.Limited, s.out.Limit = true, "stall"
			msgs = append(msgs, llm.Message{Role: "user", Content: concludeStallMsg + r.notes(spec.TaskID)})
			r.Events.Emit(progress.Event{Task: spec.TaskID, Kind: "stall_limit", Detail: i18n.T("limit.stall", r.StallSteps), Step: step})
			r.Audit.Log("stall", map[string]any{"task": spec.TaskID, "step": step, "idle_steps": idle})
		case step > maxSteps:
			s.out.Limited, s.out.Limit = true, "max_steps"
			msgs = append(msgs, llm.Message{Role: "user", Content: concludeMsg + r.notes(spec.TaskID)})
			r.Events.Emit(progress.Event{Task: spec.TaskID, Kind: "limit", Detail: i18n.T("limit", maxSteps), Step: maxSteps})
			r.Audit.Log("max_steps", map[string]any{"task": spec.TaskID, "max_steps": maxSteps})
		case late:
			s.out.Limited, s.out.Limit = true, "agent_timeout"
			msgs = append(msgs, llm.Message{Role: "user", Content: concludeTimeMsg + r.notes(spec.TaskID)})
			r.Events.Emit(progress.Event{Task: spec.TaskID, Kind: "time_limit", Detail: i18n.T("limit.time"), Step: step})
			r.Audit.Log("time_limit", map[string]any{"task": spec.TaskID, "step": step})
		}
		if !final && step > 1 && r.Inbox != nil {
			if news := r.Inbox(tools.Caller{Task: spec.TaskID, Model: s.model.Ref(), Sovereign: s.model.Sovereign}); news != "" {
				format := inboxMsg
				if r.InboxFormat != "" {
					format = r.InboxFormat
				}
				msgs = append(msgs, llm.Message{Role: "user", Content: fmt.Sprintf(format, news)})
				r.Audit.Log("inbox", map[string]any{"task": spec.TaskID, "step": step, "content": news})
			}
		}
		req := llm.Request{Messages: msgs, Session: s.id, OnProgress: s.streamProgress(step)}
		if !final {
			req.Tools = defs
		}
		resp, err := s.chat(ctx, step, req)
		if err != nil {
			return s.out, err
		}
		if resp, err = s.switchIfOutputExhausted(ctx, step, req, resp); err != nil {
			return s.out, err
		}
		msg := resp.Choices[0].Message
		msg.Role = "assistant"
		if !final && len(msg.ToolCalls) == 0 {
			if calls := leakedToolCalls(msg.Content, defs); len(calls) > 0 {
				r.Audit.Log("leaked_tool_calls", map[string]any{"task": spec.TaskID, "step": step, "model": s.out.Model, "count": len(calls), "content": truncate(msg.Content, 500)})
				msg.ToolCalls, msg.Content = calls, ""
			}
		}
		if final || len(msg.ToolCalls) == 0 {
			full := msg.Content
			for i := 0; i < maxResumes && resp.Choices[0].FinishReason == "length"; i++ {
				r.Audit.Log("truncated", map[string]any{"task": spec.TaskID, "step": step, "model": s.out.Model, "resume": i + 1})
				s.shown = full
				msgs = append(msgs, llm.Message{Role: "assistant", Content: resp.Choices[0].Message.Content}, llm.Message{Role: "user", Content: continueMsg})
				if resp, err = s.chat(ctx, step, llm.Request{Messages: msgs, Session: s.id, OnProgress: s.streamProgress(step)}); err != nil {
					return s.out, err
				}
				full += resp.Choices[0].Message.Content
			}
			s.shown = ""
			content := strings.TrimSpace(thinkBlock.ReplaceAllString(full, ""))
			for i := 0; content == "" && i < maxEmptyRetries; i++ {
				r.Audit.Log("empty_answer", map[string]any{"task": spec.TaskID, "step": step, "model": s.out.Model, "retry": i + 1})
				msgs = append(msgs, llm.Message{Role: "user", Content: emptyMsg})
				if resp, err = s.chat(ctx, step, llm.Request{Messages: msgs, Session: s.id, OnProgress: s.streamProgress(step)}); err != nil {
					return s.out, err
				}
				content = strings.TrimSpace(thinkBlock.ReplaceAllString(resp.Choices[0].Message.Content, ""))
			}
			if content == "" {
				return s.out, i18n.E("agent.empty_final")
			}
			if spec.Check != nil && checks < maxChecks {
				if problem := spec.Check(content); problem != "" {
					checks++
					idle = 0
					r.Audit.Log("answer_rejected", map[string]any{"task": spec.TaskID, "step": step, "model": s.out.Model, "problem": problem, "content": truncate(content, 2000)})
					r.Events.Emit(progress.Event{Task: spec.TaskID, Kind: "step", Model: s.out.Model, Detail: i18n.T("answer.rejected"), Step: step})
					msgs = append(msgs, llm.Message{Role: "assistant", Content: content}, llm.Message{Role: "user", Content: problem})
					continue
				}
			}
			s.out.Content = content
			return s.out, nil
		}
		for i := range msg.ToolCalls {
			if msg.ToolCalls[i].ID == "" {
				msg.ToolCalls[i].ID = fmt.Sprintf("call_%d_%d", step, i)
			}
			msg.ToolCalls[i].Type = "function"
			msg.ToolCalls[i].Function.Name = cleanToolName(msg.ToolCalls[i].Function.Name)
		}
		fresh := false
		for _, tc := range msg.ToolCalls {
			key := tc.Function.Name + "\x00" + canonicalArgs(tc.Function.Arguments)
			if !seen[key] {
				seen[key], fresh = true, true
			}
		}
		if fresh {
			idle = 0
		} else {
			idle++
		}
		msgs = append(msgs, msg)
		for _, m := range s.execTools(ctx, step, msg.ToolCalls) {
			produced = append(produced, toolMsg{idx: len(msgs), step: step})
			msgs = append(msgs, m)
		}
		r.compact(msgs, produced, step)
		if spec.Reached != nil {
			reached = spec.Reached()
		}
		lastStep = time.Since(t0)
	}
}

type toolMsg struct{ idx, step int }

func canonicalArgs(raw string) string {
	var v any
	if json.Unmarshal([]byte(raw), &v) != nil {
		return strings.TrimSpace(raw)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

var evidencePrefix = regexp.MustCompile(`^\[(E(?:\d+\.)?\d{3,})\] `)

func (r *Runner) compact(msgs []llm.Message, produced []toolMsg, step int) {
	if r.ToolChars <= 0 || r.KeepSteps <= 0 {
		return
	}
	for _, p := range produced {
		if p.step > step-r.KeepSteps {
			break
		}
		m := &msgs[p.idx]
		id := evidencePrefix.FindStringSubmatch(m.Content)
		if id == nil || len(m.Content) <= r.ToolChars || strings.Contains(m.Content, compactMark) {
			continue
		}
		cut := r.ToolChars
		for cut > 0 && !utf8.RuneStart(m.Content[cut]) {
			cut--
		}
		m.Content = m.Content[:cut] + fmt.Sprintf("\n%s (%d caractères au total) : relire avec evidence_read id=%s, avec pattern ou offset]", compactMark, len(m.Content), id[1])
	}
}

const compactMark = "[… sortie raccourcie dans l'historique"

func (r *Runner) notes(task string) string {
	if r.ConcludeNotes == nil {
		return ""
	}
	if n := strings.TrimSpace(r.ConcludeNotes(task)); n != "" {
		return "\nTes notes enregistrées en mémoire pendant cette tâche :\n" + n
	}
	return ""
}

func outputExhausted(resp *llm.Response) bool {
	c := resp.Choices[0]
	return c.FinishReason == "length" && len(c.Message.ToolCalls) == 0 && strings.TrimSpace(thinkBlock.ReplaceAllString(c.Message.Content, "")) == ""
}

func (s *session) switchIfOutputExhausted(ctx context.Context, step int, req llm.Request, resp *llm.Response) (*llm.Response, error) {
	cands := s.spec.Candidates
	tried := map[string]bool{}
	for outputExhausted(resp) {
		from := s.model.Ref()
		tried[from] = true
		next := -1
		for k := 1; k < len(cands); k++ {
			i := (s.cur + k) % len(cands)
			if !tried[cands[i].Ref()] && s.r.unavailable(cands[i]) == "" {
				next = i
				break
			}
		}
		if next < 0 {
			s.r.Audit.Log("output_exhausted", map[string]any{"task": s.spec.TaskID, "step": step, "model": from, "completion_tokens": resp.Usage.CompletionTokens, "next": ""})
			return nil, i18n.E("agent.exhausted", from, resp.Usage.CompletionTokens)
		}
		s.cur = next
		s.r.Audit.Log("output_exhausted", map[string]any{"task": s.spec.TaskID, "step": step, "model": from, "completion_tokens": resp.Usage.CompletionTokens, "next": cands[next].Ref()})
		s.r.Events.Emit(progress.Event{Task: s.spec.TaskID, Kind: "fallback", Model: cands[next].Ref(), Detail: i18n.T("fallback.exhausted", from)})
		var err error
		if resp, err = s.chat(ctx, step, req); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func (s *session) chat(ctx context.Context, step int, req llm.Request) (*llm.Response, error) {
	r := s.r
	attempts := max(r.Attempts, 1)
	cands := s.spec.Candidates
	rounds := 1
	if r.RoundPause > 0 {
		rounds = 2
	}
	var lastErr error
	var skipped []string
	persistent := false
	for round := 0; ; round++ {
		if round > 0 {
			if lastErr == nil || !llm.Transient(lastErr) || round >= rounds && !persistent {
				break
			}
			pause := r.RoundPause
			if persistent {
				pause = min(r.RoundPause<<min(round-1, 4), maxRoundPause)
				if ra := llm.RetryAfter(lastErr); ra > pause {
					pause = min(ra, maxRoundPause)
				}
			}
			r.Events.Emit(progress.Event{Task: s.spec.TaskID, Kind: "fallback", Model: cands[s.cur].Ref(), Detail: i18n.T("fallback.round", truncate(lastErr.Error(), 120), pause)})
			r.Audit.Log("retry_round", map[string]any{"task": s.spec.TaskID, "step": step, "round": round, "pause": pause.String(), "persistent": persistent, "error": lastErr.Error()})
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(pause):
			}
			lastErr, skipped, persistent = nil, nil, false
		}
		for k := 0; k < len(cands); k++ {
			i := (s.cur + k) % len(cands)
			m := cands[i]
			if reason := r.unavailable(m); reason != "" {
				skipped = append(skipped, m.Ref()+" ("+reason+")")
				continue
			}
			req.Model = m.ID
			req.MaxTokens = min(m.MaxOutput, maxOutputTokens)
			sent := req
			if s.spec.OnText != nil {
				sent.OnContent = liveText(s.spec.OnText, s.shown)
			}
			if !m.Sovereign {
				sent.Messages = r.boundary().Outbound(m, req.Messages)
			}
			var err error
			for attempt := 1; attempt <= attempts; attempt++ {
				t0 := time.Now()
				tm := &llm.Timing{}
				sent.Timing = tm
				var resp *llm.Response
				resp, err = r.Chat.Chat(ctx, m.Provider, sent)
				rec := map[string]any{"task": s.spec.TaskID, "role": s.spec.Role, "model": m.Ref(), "step": step, "attempt": attempt, "duration_ms": time.Since(t0).Milliseconds(), "tools_offered": len(req.Tools), "max_tokens": sent.MaxTokens}
				for k, d := range map[string]time.Duration{"queue_ms": tm.Queue, "headers_ms": tm.Headers, "first_chunk_ms": tm.FirstChunk} {
					if d >= time.Millisecond {
						rec[k] = d.Milliseconds()
					}
				}
				if err == nil && !resp.Cost.Reported && (m.InputCost > 0 || m.OutputCost > 0) && resp.Usage.PromptTokens+resp.Usage.CompletionTokens > 0 {
					resp.Cost.Response = float64(resp.Usage.PromptTokens)*m.InputCost + float64(resp.Usage.CompletionTokens)*m.OutputCost
					resp.Cost.Reported, resp.Cost.Estimated = true, true
				}
				if err != nil {
					rec["error"] = err.Error()
				} else {
					rec["cost"] = resp.Cost.Response
					rec["prompt_tokens"] = resp.Usage.PromptTokens
					rec["completion_tokens"] = resp.Usage.CompletionTokens
					rec["finish_reason"] = resp.Choices[0].FinishReason
					rec["content_chars"] = len(resp.Choices[0].Message.Content)
					rec["reasoning_chars"] = resp.ReasoningChars
					var names []string
					for _, tc := range resp.Choices[0].Message.ToolCalls {
						names = append(names, tc.Function.Name)
					}
					rec["tool_calls"] = names
				}
				r.Audit.Log("llm_call", rec)
				if err == nil {
					if !m.Sovereign {
						resp.Choices[0].Message = r.boundary().Inbound(m, resp.Choices[0].Message)
					}
					s.cur = i
					s.model = m
					s.out.Model = m.Ref()
					s.out.Sovereign = m.Sovereign
					s.out.Usage.PromptTokens += resp.Usage.PromptTokens
					s.out.Usage.CompletionTokens += resp.Usage.CompletionTokens
					s.out.Cost += resp.Cost.Response
					if reason := r.Budget.Record(m.Provider, resp.Cost); reason != "" {
						r.Events.Emit(progress.Event{Task: s.spec.TaskID, Kind: "budget", Model: m.Provider, Detail: i18n.T("budget.dropped", reason)})
						r.Audit.Log("budget_exhausted", map[string]any{"provider": m.Provider, "reason": reason})
					}
					r.Events.Emit(progress.Event{Task: s.spec.TaskID, Kind: "step", Model: m.Ref(), Detail: fmt.Sprintf("%d", step), Step: step})
					return resp, nil
				}
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				if !llm.Transient(err) || attempt == attempts {
					break
				}
				wait := r.Backoff * time.Duration(attempt)
				if ra := llm.RetryAfter(err); ra > wait {
					wait = min(ra, 30*time.Second)
				}
				r.Events.Emit(progress.Event{Task: s.spec.TaskID, Kind: "retry", Model: m.Ref(), Detail: i18n.T("retry", attempt, m.Ref(), truncate(err.Error(), 120), wait)})
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(wait):
				}
			}
			lastErr = err
			if r.RoundPause > 0 && r.Persistent != nil && llm.Transient(err) && r.Persistent(m.Provider) {
				persistent = true
			}
			if !llm.Failover(err) {
				return nil, fmt.Errorf("%s: %w", m.Ref(), err)
			}
			if llm.Unavailable(err) {
				if _, loaded := r.down.LoadOrStore(m.Ref(), true); !loaded {
					r.Events.Emit(progress.Event{Task: s.spec.TaskID, Kind: "dropped", Model: m.Ref(), Detail: i18n.T("dropped", truncate(err.Error(), 120))})
					r.Audit.Log("model_down", map[string]any{"model": m.Ref(), "error": err.Error()})
				}
			}
			if k+1 < len(cands) {
				next := cands[(i+1)%len(cands)]
				r.Events.Emit(progress.Event{Task: s.spec.TaskID, Kind: "fallback", Model: next.Ref(), Detail: i18n.T("fallback.after", m.Ref(), truncate(err.Error(), 120))})
			}
		}
	}
	if lastErr == nil {
		return nil, i18n.E("agent.none_list", strings.Join(skipped, ", "))
	}
	return nil, i18n.E("agent.all_failed", lastErr)
}

func (s *session) execTools(ctx context.Context, step int, calls []llm.ToolCall) []llm.Message {
	out := make([]llm.Message, len(calls))
	var wg sync.WaitGroup
	for i, tc := range calls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.r.Events.Emit(progress.Event{Task: s.spec.TaskID, Kind: "tool", Detail: tc.Function.Name + " " + truncate(tc.Function.Arguments, 140)})
			t0 := time.Now()
			cctx := tools.WithCaller(ctx, tools.Caller{Task: s.spec.TaskID, Model: s.model.Ref(), Sovereign: s.model.Sovereign})
			res, err := s.r.Tools.Call(cctx, s.spec.Tools, tc.Function.Name, tc.Function.Arguments)
			rec := map[string]any{"task": s.spec.TaskID, "step": step, "tool": tc.Function.Name, "args": tc.Function.Arguments, "duration_ms": time.Since(t0).Milliseconds(), "output_bytes": len(res)}
			if err != nil {
				rec["error"] = err.Error()
				res = "ERREUR: " + err.Error()
			}
			if s.r.Evidence != nil && !strings.HasPrefix(tc.Function.Name, "memory_") && !strings.HasPrefix(tc.Function.Name, "evidence_") {
				id := s.r.Evidence.Add(s.spec.TaskID, tc.Function.Name, tc.Function.Arguments, res, err)
				rec["evidence"] = id
				if s.r.Journal && tc.Function.Name != lead.ToolName {
					s.r.Events.Emit(progress.Event{Task: s.spec.TaskID, Kind: "evidence", Detail: journalLine(id, tc.Function.Name, tc.Function.Arguments, len(res), time.Since(t0), err)})
				}
				res = "[" + id + "] " + s.r.Tools.Clip(res, id)
			} else {
				res = s.r.Tools.Clip(res, "")
			}
			s.r.Audit.Log("tool_call", rec)
			out[i] = llm.Message{Role: "tool", ToolCallID: tc.ID, Content: res}
		}()
	}
	wg.Wait()
	s.out.ToolCalls += len(calls)
	return out
}

func (s *session) streamProgress(step int) func(llm.StreamProgress) {
	var last time.Time
	return func(p llm.StreamProgress) {
		now := time.Now()
		if now.Sub(last) < 250*time.Millisecond {
			return
		}
		last = now
		var detail string
		switch {
		case p.ToolCalls > 0:
			detail = i18n.T("stream.tools", p.ToolCalls, approxTokens(p.Chunks))
		case p.ContentChars > 0:
			detail = i18n.T("stream.writing", approxTokens(p.Chunks))
		default:
			detail = i18n.T("stream.reasoning", approxTokens(p.Chunks))
		}
		s.r.Events.Emit(progress.Event{Task: s.spec.TaskID, Kind: "stream", Model: s.spec.Candidates[s.cur].Ref(), Detail: detail, Step: step})
	}
}

func liveText(show func(string), prefix string) func(string) {
	var b strings.Builder
	b.WriteString(prefix)
	show(visibleText(prefix))
	return func(delta string) {
		b.WriteString(delta)
		show(visibleText(b.String()))
	}
}

func visibleText(s string) string {
	s = thinkBlock.ReplaceAllString(s, "")
	if i := strings.Index(s, "<think>"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimLeft(s, " \n")
}

func approxTokens(chunks int) string {
	if chunks >= 1000 {
		return fmt.Sprintf("~%.1fk tok", float64(chunks)/1000)
	}
	return fmt.Sprintf("~%d tok", chunks)
}

func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func journalLine(id, tool, args string, size int, d time.Duration, err error) string {
	args = truncate(strings.Join(strings.Fields(args), " "), 300)
	if err != nil {
		return i18n.T("journal.error", id, tool, args, truncate(err.Error(), 200))
	}
	return i18n.T("journal.evidence", id, tool, args, size, d.Truncate(time.Millisecond))
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func cleanToolName(name string) string {
	if i := strings.Index(name, "<|"); i > 0 {
		name = name[:i]
	}
	return strings.TrimSpace(name)
}

func leakedToolCalls(content string, defs []llm.ToolDef) []llm.ToolCall {
	var out []llm.ToolCall
	for _, m := range leakedCall.FindAllStringSubmatchIndex(content, -1) {
		name := cleanToolName(content[m[2]:m[3]])
		if !slices.ContainsFunc(defs, func(d llm.ToolDef) bool { return d.Function.Name == name }) {
			continue
		}
		rest := content[m[1]:]
		i := strings.IndexByte(rest, '{')
		if i < 0 || strings.Contains(rest[:i], "to=functions.") {
			continue
		}
		var args json.RawMessage
		if err := json.NewDecoder(strings.NewReader(rest[i:])).Decode(&args); err != nil {
			continue
		}
		out = append(out, llm.ToolCall{Type: "function", Function: llm.FunctionCall{Name: name, Arguments: string(args)}})
	}
	return out
}
