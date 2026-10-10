package catalog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/agardenat/clotr/internal/config"
)

func provider(t *testing.T, models string, info string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/models", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(models))
	})
	if info != "" {
		mux.HandleFunc("GET /model/info", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(info)) })
	}
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func TestLoad(t *testing.T) {
	t.Setenv("KEY", "k")
	a := provider(t, `{"data":[{"id":"big-opus"},{"id":"embed-x"},{"id":"other"}]}`, "")
	b := provider(t, `{"data":[{"id":"qwen:7b"}]}`, `{"data":[{"model_name":"qwen:7b","model_info":{"max_input_tokens":32000,"supports_function_calling":true}}]}`)
	cfg, err := config.Parse([]byte(`
providers:
  - {name: a, base_url: ` + a.URL + `/v1, api_key_env: KEY, weight: 5, sovereign: true}
  - {name: b, base_url: ` + b.URL + `/v1, api_key_env: KEY, model_info: true}
profiles:
  - {match: "*embed*", exclude: true}
  - {match: "*opus*", tier: deep, context: 200000, tools: true}
  - {match: "b/qwen*", tier: fast, sovereign: true}
`))
	if err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(t.TempDir(), "c.json")
	cat, err := Load(context.Background(), cfg, http.DefaultClient, cache, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Models) != 3 {
		t.Fatalf("modèles: %+v", cat.Models)
	}
	opus, _ := cat.Find("a/big-opus")
	if opus.Tier != "deep" || !opus.Tools || opus.Context != 200000 || !opus.Sovereign || opus.Weight != 5 {
		t.Fatalf("opus: %+v", opus)
	}
	qwen, _ := cat.Find("b/qwen:7b")
	if qwen.Tier != "fast" || !qwen.Tools || qwen.Context != 32000 || !qwen.Sovereign {
		t.Fatalf("qwen: %+v", qwen)
	}
	other, _ := cat.Find("a/other")
	if other.Tier != "balanced" || other.Tools || len(cat.Warnings) != 1 {
		t.Fatalf("other: %+v warnings=%v", other, cat.Warnings)
	}
	a.Close()
	cached, err := Load(context.Background(), cfg, http.DefaultClient, cache, false)
	if err != nil || !cached.FromCache || len(cached.Models) != 3 {
		t.Fatalf("cache: %v %+v", err, cached)
	}
}

func TestAllProvidersDown(t *testing.T) {
	cfg, _ := config.Parse([]byte("providers:\n  - {name: a, base_url: http://127.0.0.1:1/v1}\n"))
	if _, err := Load(context.Background(), cfg, http.DefaultClient, "", true); err == nil {
		t.Fatal("erreur attendue")
	}
}

func TestGlob(t *testing.T) {
	re := Glob("*opus*")
	for _, s := range []string{"anthropic/claude-opus-5", "OPUS"} {
		if !re.MatchString(s) {
			t.Errorf("%s devrait matcher", s)
		}
	}
	if Glob("qwen?").MatchString("qwen12") {
		t.Error("? ne doit matcher qu'un caractère")
	}
}
