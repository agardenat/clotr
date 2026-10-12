package websearch

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/agardenat/clotr/internal/config"
	"github.com/agardenat/clotr/internal/httpx"
	"github.com/agardenat/clotr/internal/tools"
)

const Name = "web_search"

const instructions = "Réponds à la question à partir d'une recherche web, dans la langue de la question. Privilégie la documentation officielle de l'éditeur et ses bases de connaissances. Chaque affirmation s'appuie sur une page lue, dont tu donnes l'URL. Si la recherche ne permet pas de répondre, dis-le explicitement, sans supposition."

type Tool struct {
	api           string
	url           string
	model         string
	ref           string
	apiKey        string
	headers       map[string]string
	sessionHeader string
	session       string
	hc            *http.Client
}

func New(p config.Provider, model, api string, timeout time.Duration) (*Tool, error) {
	var path string
	switch api {
	case "messages":
		path = "/messages"
	case "responses":
		path = "/responses"
	default:
		return nil, fmt.Errorf("web_search.api: %q invalide (messages|responses)", api)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &Tool{
		api:           api,
		url:           strings.TrimSuffix(p.BaseURL, "/") + path,
		model:         model,
		ref:           p.Name + "/" + model,
		apiKey:        p.APIKey(),
		headers:       p.Headers,
		sessionHeader: p.SessionHeader,
		session:       hex.EncodeToString(id),
		hc:            &http.Client{Timeout: timeout},
	}, nil
}

func (t *Tool) Name() string { return Name }

func (t *Tool) Ref() string { return t.ref }

func (t *Tool) Description() string {
	return "Recherche sur le web (recherche native du modèle " + t.ref + ") : pose une question précise et générique (produit, version, message d'erreur sans identifiant interne). Renvoie une réponse rédigée à partir des pages lues, les URL citées et les requêtes lancées. Une question par appel ; ne relance pas une question déjà posée."
}

func (t *Tool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","description":"question à rechercher, ex: \"valeur par défaut de dfs.namenode.handler.count dans Hadoop 3.1\""}},"required":["query"]}`)
}

type result struct {
	text     string
	sources  []source
	queries  []string
	searches int
	in, out  int
}

type source struct{ title, url string }

var urlPattern = regexp.MustCompile(`https?://[^\s<>"'()\[\]]+`)

func (r *result) addTextSources() {
	for _, u := range urlPattern.FindAllString(r.text, -1) {
		r.addSource("", strings.TrimRight(u, ".,;:!?*`"))
	}
}

func (r *result) addSource(title, url string) {
	if url == "" {
		return
	}
	for _, s := range r.sources {
		if s.url == url {
			return
		}
	}
	r.sources = append(r.sources, source{title, url})
}

func (t *Tool) Call(ctx context.Context, raw json.RawMessage) (string, error) {
	a, err := tools.Decode[struct {
		Query string `json:"query"`
	}](raw)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(a.Query) == "" {
		return "", fmt.Errorf("query vide")
	}
	var r *result
	if t.api == "messages" {
		r, err = t.messages(ctx, a.Query)
	} else {
		r, err = t.responses(ctx, a.Query)
	}
	if err != nil {
		return "", err
	}
	r.addTextSources()
	return r.render(t.ref), nil
}

func (r *result) render(ref string) string {
	var b strings.Builder
	b.WriteString(strings.TrimSpace(r.text))
	if len(r.sources) > 0 {
		b.WriteString("\n\nSources :\n")
		for _, s := range r.sources {
			if s.title != "" {
				fmt.Fprintf(&b, "- %s — %s\n", s.title, s.url)
			} else {
				fmt.Fprintf(&b, "- %s\n", s.url)
			}
		}
	} else {
		b.WriteString("\n\nSources : aucune URL citée, réponse non étayée par une page lue.\n")
	}
	if len(r.queries) > 0 {
		fmt.Fprintf(&b, "Requêtes : %s\n", strings.Join(r.queries, " ; "))
	}
	fmt.Fprintf(&b, "Recherche : %s, %d recherche(s), %d tokens en entrée, %d en sortie", ref, r.searches, r.in, r.out)
	return b.String()
}

func (t *Tool) post(ctx context.Context, body any, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", httpx.UserAgent)
	if t.apiKey != "" {
		if t.api == "messages" {
			req.Header.Set("x-api-key", t.apiKey)
		} else {
			req.Header.Set("Authorization", "Bearer "+t.apiKey)
		}
	}
	if t.api == "messages" {
		req.Header.Set("anthropic-version", "2023-06-01")
	}
	if t.sessionHeader != "" {
		req.Header.Set(t.sessionHeader, t.session)
	}
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	resp, err := t.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: HTTP %d: %s", t.ref, resp.StatusCode, strings.TrimSpace(string(payload[:min(len(payload), 2000)])))
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("%s: réponse illisible: %w", t.ref, err)
	}
	return nil
}

type anthropicBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`
	Citations []struct {
		URL   string `json:"url"`
		Title string `json:"title"`
	} `json:"citations,omitempty"`
}

type anthropicResponse struct {
	Content    []json.RawMessage `json:"content"`
	StopReason string            `json:"stop_reason"`
	Usage      struct {
		InputTokens   int `json:"input_tokens"`
		OutputTokens  int `json:"output_tokens"`
		ServerToolUse struct {
			WebSearchRequests int `json:"web_search_requests"`
		} `json:"server_tool_use"`
	} `json:"usage"`
}

func (t *Tool) messages(ctx context.Context, query string) (*result, error) {
	msgs := []map[string]any{{"role": "user", "content": query}}
	r := &result{}
	var texts []string
	for {
		var resp anthropicResponse
		body := map[string]any{
			"model":      t.model,
			"max_tokens": 8192,
			"system":     instructions,
			"messages":   msgs,
			"tools":      []map[string]any{{"type": "web_search_20250305", "name": "web_search"}},
		}
		if err := t.post(ctx, body, &resp); err != nil {
			return nil, err
		}
		r.in += resp.Usage.InputTokens
		r.out += resp.Usage.OutputTokens
		r.searches += resp.Usage.ServerToolUse.WebSearchRequests
		var text strings.Builder
		for _, rawBlock := range resp.Content {
			var b anthropicBlock
			if json.Unmarshal(rawBlock, &b) != nil {
				continue
			}
			switch b.Type {
			case "text":
				text.WriteString(b.Text)
				for _, c := range b.Citations {
					r.addSource(c.Title, c.URL)
				}
			case "server_tool_use":
				var in struct {
					Query string `json:"query"`
				}
				if json.Unmarshal(b.Input, &in) == nil && in.Query != "" {
					r.queries = append(r.queries, in.Query)
				}
			case "web_search_tool_result":
				var e struct {
					ErrorCode string `json:"error_code"`
				}
				if json.Unmarshal(b.Content, &e) == nil && e.ErrorCode != "" {
					texts = append(texts, "Erreur de recherche : "+e.ErrorCode)
				}
			}
		}
		if s := strings.TrimSpace(text.String()); s != "" {
			texts = append(texts, s)
		}
		if resp.StopReason != "pause_turn" || len(resp.Content) == 0 {
			break
		}
		msgs = append(msgs, map[string]any{"role": "assistant", "content": resp.Content})
	}
	if r.searches == 0 {
		r.searches = len(r.queries)
	}
	r.text = strings.Join(texts, "\n\n")
	if r.text == "" {
		return nil, fmt.Errorf("%s: réponse sans texte", t.ref)
	}
	return r, nil
}

type responsesOutput struct {
	Type   string `json:"type"`
	Action struct {
		Type  string `json:"type"`
		Query string `json:"query"`
	} `json:"action"`
	Content []struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		Annotations []struct {
			Type  string `json:"type"`
			URL   string `json:"url"`
			Title string `json:"title"`
		} `json:"annotations"`
	} `json:"content"`
}

type responsesResponse struct {
	Status            string            `json:"status"`
	Output            []responsesOutput `json:"output"`
	IncompleteDetails *struct {
		Reason string `json:"reason"`
	} `json:"incomplete_details"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func (t *Tool) responses(ctx context.Context, query string) (*result, error) {
	var resp responsesResponse
	body := map[string]any{
		"model":        t.model,
		"instructions": instructions,
		"input":        query,
		"tools":        []map[string]any{{"type": "web_search"}},
	}
	if err := t.post(ctx, body, &resp); err != nil {
		return nil, err
	}
	r := &result{in: resp.Usage.InputTokens, out: resp.Usage.OutputTokens}
	var text strings.Builder
	for _, o := range resp.Output {
		switch o.Type {
		case "web_search_call":
			r.searches++
			if o.Action.Query != "" {
				r.queries = append(r.queries, o.Action.Query)
			}
		case "message":
			for _, c := range o.Content {
				if c.Type != "output_text" {
					continue
				}
				text.WriteString(c.Text)
				for _, an := range c.Annotations {
					if an.Type == "url_citation" {
						r.addSource(an.Title, an.URL)
					}
				}
			}
		}
	}
	r.text = text.String()
	if resp.Status == "incomplete" && resp.IncompleteDetails != nil {
		r.text += "\n\n(réponse incomplète : " + resp.IncompleteDetails.Reason + ")"
	}
	if strings.TrimSpace(r.text) == "" {
		return nil, fmt.Errorf("%s: réponse sans texte (statut %s)", t.ref, resp.Status)
	}
	return r, nil
}
