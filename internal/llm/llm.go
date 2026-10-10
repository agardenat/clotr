package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/httpx"
)

type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

func (m *Message) UnmarshalJSON(data []byte) error {
	var raw struct {
		Role       string          `json:"role"`
		Content    json.RawMessage `json:"content"`
		ToolCalls  []ToolCall      `json:"tool_calls"`
		ToolCallID string          `json:"tool_call_id"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	m.Role, m.ToolCalls, m.ToolCallID = raw.Role, raw.ToolCalls, raw.ToolCallID
	m.Content = ""
	if len(raw.Content) == 0 || string(raw.Content) == "null" {
		return nil
	}
	if err := json.Unmarshal(raw.Content, &m.Content); err == nil {
		return nil
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw.Content, &parts); err != nil {
		return fmt.Errorf("content: format non supporté")
	}
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(p.Text)
	}
	m.Content = b.String()
	return nil
}

type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

func (f *FunctionCall) UnmarshalJSON(data []byte) error {
	var raw struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	f.Name = raw.Name
	f.Arguments = ""
	if len(raw.Arguments) == 0 || string(raw.Arguments) == "null" {
		return nil
	}
	if err := json.Unmarshal(raw.Arguments, &f.Arguments); err == nil {
		return nil
	}
	f.Arguments = string(raw.Arguments)
	return nil
}

type ToolDef struct {
	Type     string      `json:"type"`
	Function FunctionDef `json:"function"`
}

type FunctionDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type Request struct {
	Model         string               `json:"model"`
	Messages      []Message            `json:"messages"`
	Tools         []ToolDef            `json:"tools,omitempty"`
	Temperature   *float64             `json:"temperature,omitempty"`
	MaxTokens     int                  `json:"max_tokens,omitempty"`
	Stream        bool                 `json:"stream,omitempty"`
	StreamOptions *StreamOptions       `json:"stream_options,omitempty"`
	Session       string               `json:"-"`
	OnProgress    func(StreamProgress) `json:"-"`
	OnContent     func(delta string)   `json:"-"`
}

type StreamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

type Response struct {
	Choices        []Choice `json:"choices"`
	Usage          Usage    `json:"usage"`
	Cost           Cost     `json:"-"`
	ReasoningChars int      `json:"-"`
}

type Cost struct {
	Reported  bool
	Estimated bool
	Response  float64
	KeySpend  float64
	KeyMax    float64
	HasKey    bool
}

func parseCost(h http.Header) Cost {
	var c Cost
	num := func(k string) (float64, bool) {
		v := h.Get(k)
		if v == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(v, 64)
		return f, err == nil
	}
	c.Response, c.Reported = num("x-litellm-response-cost")
	spend, okS := num("x-litellm-key-spend")
	max, okM := num("x-litellm-key-max-budget")
	if okS && okM && max > 0 {
		c.KeySpend, c.KeyMax, c.HasKey = spend, max, true
	}
	return c
}

type Choice struct {
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

type APIError struct {
	Status     int
	Body       string
	RetryAfter time.Duration
}

func RetryAfter(err error) time.Duration {
	var api *APIError
	if errors.As(err, &api) {
		return api.RetryAfter
	}
	return 0
}

func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func (e *APIError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body)
}

var ErrRequestTimeout = errors.New("request_timeout dépassé")

func Transient(err error) bool {
	if err == nil || errors.Is(err, ErrRequestTimeout) {
		return false
	}
	var api *APIError
	if errors.As(err, &api) {
		return api.Status == 408 || api.Status == 425 || api.Status == 429 || api.Status >= 500
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := err.Error()
	for _, frag := range []string{"stream error", "GOAWAY", "INTERNAL_ERROR", "connection reset by peer", "broken pipe"} {
		if strings.Contains(msg, frag) {
			return true
		}
	}
	return false
}

func quotaExceeded(api *APIError) bool {
	if api.Status != 403 {
		return false
	}
	b := strings.ToLower(api.Body)
	return strings.Contains(b, "quota") || strings.Contains(b, "budget") || strings.Contains(b, "insufficient")
}

func Unavailable(err error) bool {
	var api *APIError
	if !errors.As(err, &api) {
		return false
	}
	return api.Status == 404
}

func Failover(err error) bool {
	if Transient(err) || errors.Is(err, ErrRequestTimeout) {
		return true
	}
	var api *APIError
	if errors.As(err, &api) {
		return api.Status == 400 || api.Status == 404 || api.Status == 422 || quotaExceeded(api)
	}
	return false
}

type Client struct {
	baseURL        string
	apiKey         string
	headers        map[string]string
	sessionHeader  string
	stream         bool
	requestTimeout time.Duration
	idleTimeout    time.Duration
	hc             *http.Client
}

func NewClient(p config.Provider, limits config.Limits, hc *http.Client) *Client {
	return &Client{
		baseURL:        p.BaseURL,
		apiKey:         p.APIKey(),
		headers:        p.Headers,
		sessionHeader:  p.SessionHeader,
		stream:         p.Stream == nil || *p.Stream,
		requestTimeout: limits.RequestTimeout.Duration,
		idleTimeout:    limits.IdleTimeout.Duration,
		hc:             hc,
	}
}

type StreamProgress struct {
	Chunks         int
	ContentChars   int
	ReasoningChars int
	ToolCalls      int
}

func (c *Client) newRequest(ctx context.Context, req Request) (*http.Request, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("User-Agent", httpx.UserAgent)
	if c.sessionHeader != "" && req.Session != "" {
		hreq.Header.Set(c.sessionHeader, req.Session)
	}
	if c.apiKey != "" {
		hreq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	for k, v := range c.headers {
		hreq.Header.Set(k, v)
	}
	return hreq, nil
}

func apiError(resp *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return &APIError{Status: resp.StatusCode, Body: httpx.Snippet(data, 500), RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
}

func (c *Client) Chat(ctx context.Context, req Request) (*Response, error) {
	rctx := ctx
	if c.requestTimeout > 0 {
		var cancel context.CancelFunc
		rctx, cancel = context.WithTimeout(ctx, c.requestTimeout)
		defer cancel()
	}
	var resp *Response
	var err error
	if c.stream {
		resp, err = c.chatStream(rctx, req)
	} else {
		resp, err = c.chatOnce(rctx, req)
	}
	if err != nil && ctx.Err() == nil && errors.Is(rctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("%w (%s)", ErrRequestTimeout, c.requestTimeout)
	}
	return resp, err
}

func (c *Client) chatOnce(ctx context.Context, req Request) (*Response, error) {
	hreq, err := c.newRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp)
	}
	return decodeResponse(resp)
}

func decodeResponse(resp *http.Response) (*Response, error) {
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out Response
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("réponse invalide: %w", err)
	}
	if len(out.Choices) == 0 {
		return nil, &APIError{Status: 502, Body: "réponse sans choices"}
	}
	out.Cost = parseCost(resp.Header)
	return &out, nil
}

type streamChunk struct {
	Choices []struct {
		Delta struct {
			Content          *string `json:"content"`
			ReasoningContent *string `json:"reasoning_content"`
			Reasoning        *string `json:"reasoning"`
			ToolCalls        []struct {
				Index    *int   `json:"index"`
				ID       string `json:"id"`
				Function struct {
					Name      string          `json:"name"`
					Arguments json.RawMessage `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
	Usage *Usage `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

type toolAcc struct {
	id, name string
	args     strings.Builder
}

func (c *Client) chatStream(ctx context.Context, req Request) (*Response, error) {
	req.Stream = true
	req.StreamOptions = &StreamOptions{IncludeUsage: true}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var idleFired atomic.Bool
	var idle *time.Timer
	if c.idleTimeout > 0 {
		idle = time.AfterFunc(c.idleTimeout, func() {
			idleFired.Store(true)
			cancel()
		})
		defer idle.Stop()
	}
	idleErr := func(err error) error {
		if idleFired.Load() {
			return fmt.Errorf("aucune donnée reçue depuis %s: %w", c.idleTimeout, context.DeadlineExceeded)
		}
		return err
	}
	hreq, err := c.newRequest(sctx, req)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(hreq)
	if err != nil {
		return nil, idleErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return decodeResponse(resp)
	}
	var (
		content  strings.Builder
		tools    = map[int]*toolAcc{}
		order    []int
		finish   string
		usage    Usage
		progress StreamProgress
	)
	br := bufio.NewReaderSize(resp.Body, 64<<10)
	for {
		line, err := br.ReadString('\n')
		if idle != nil && line != "" {
			idle.Reset(c.idleTimeout)
		}
		line = strings.TrimSpace(line)
		if data, ok := strings.CutPrefix(line, "data:"); ok {
			data = strings.TrimSpace(data)
			if data == "[DONE]" {
				break
			}
			var ch streamChunk
			if jerr := json.Unmarshal([]byte(data), &ch); jerr != nil {
				return nil, fmt.Errorf("flux invalide: %w", jerr)
			}
			if ch.Error != nil {
				return nil, &APIError{Status: 502, Body: httpx.Snippet([]byte(ch.Error.Message), 500)}
			}
			if ch.Usage != nil {
				usage = *ch.Usage
			}
			for _, choice := range ch.Choices {
				d := choice.Delta
				if d.Content != nil {
					content.WriteString(*d.Content)
					progress.ContentChars += len(*d.Content)
					if req.OnContent != nil && *d.Content != "" {
						req.OnContent(*d.Content)
					}
				}
				for _, r := range []*string{d.ReasoningContent, d.Reasoning} {
					if r != nil {
						progress.ReasoningChars += len(*r)
					}
				}
				for i, tc := range d.ToolCalls {
					idx := i
					if tc.Index != nil {
						idx = *tc.Index
					}
					acc, ok := tools[idx]
					if !ok {
						acc = &toolAcc{}
						tools[idx] = acc
						order = append(order, idx)
						progress.ToolCalls++
					}
					if tc.ID != "" {
						acc.id = tc.ID
					}
					acc.name += tc.Function.Name
					if len(tc.Function.Arguments) > 0 && string(tc.Function.Arguments) != "null" {
						var s string
						if json.Unmarshal(tc.Function.Arguments, &s) == nil {
							acc.args.WriteString(s)
						} else {
							acc.args.Write(tc.Function.Arguments)
						}
					}
				}
				if choice.FinishReason != nil && *choice.FinishReason != "" {
					finish = *choice.FinishReason
				}
			}
			progress.Chunks++
			if req.OnProgress != nil {
				req.OnProgress(progress)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, idleErr(err)
		}
	}
	if progress.Chunks == 0 {
		return nil, &APIError{Status: 502, Body: "flux vide"}
	}
	sort.Ints(order)
	msg := Message{Role: "assistant", Content: content.String()}
	for _, idx := range order {
		acc := tools[idx]
		msg.ToolCalls = append(msg.ToolCalls, ToolCall{ID: acc.id, Type: "function", Function: FunctionCall{Name: acc.name, Arguments: acc.args.String()}})
	}
	return &Response{Choices: []Choice{{Message: msg, FinishReason: finish}}, Usage: usage, Cost: parseCost(resp.Header), ReasoningChars: progress.ReasoningChars}, nil
}

type Chatter interface {
	Chat(ctx context.Context, provider string, req Request) (*Response, error)
}

type Pool struct {
	clients map[string]*Client
	sems    map[string]*semaphore.Weighted
}

func NewPool(cfg *config.Config, hc *http.Client) *Pool {
	p := &Pool{clients: map[string]*Client{}, sems: map[string]*semaphore.Weighted{}}
	for _, prov := range cfg.Providers {
		p.clients[prov.Name] = NewClient(prov, cfg.Limits, hc)
		p.sems[prov.Name] = semaphore.NewWeighted(int64(prov.MaxConcurrency))
	}
	return p
}

func (p *Pool) Chat(ctx context.Context, provider string, req Request) (*Response, error) {
	c, ok := p.clients[provider]
	if !ok {
		return nil, fmt.Errorf("provider %q inconnu", provider)
	}
	sem := p.sems[provider]
	if err := sem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer sem.Release(1)
	return c.Chat(ctx, req)
}
