package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestReadWriteDelete(t *testing.T) {
	var mu sync.Mutex
	store := map[string]map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("X-Vault-Token") != "tok" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch r.Method {
		case http.MethodPost:
			var d map[string]string
			if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			store[r.URL.EscapedPath()] = d
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			delete(store, r.URL.EscapedPath())
			w.WriteHeader(http.StatusNoContent)
		default:
			d, ok := store[r.URL.EscapedPath()]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"errors":[]}`))
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": d})
		}
	}))
	defer srv.Close()
	c := &Client{Addr: srv.URL, Token: "tok", HTTP: srv.Client()}
	ctx := context.Background()
	if d, err := c.ReadData(ctx, "cubbyhole/clotr/a b"); err != nil || d != nil {
		t.Fatalf("absent : %v %v", d, err)
	}
	if err := c.Write(ctx, "cubbyhole/clotr/a b", map[string]string{"password": "p"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := store["/v1/cubbyhole/clotr/a%20b"]; !ok {
		t.Fatalf("chemin non échappé : %v", store)
	}
	if d, err := c.ReadData(ctx, "/cubbyhole/clotr/a b"); err != nil || d["password"] != "p" {
		t.Fatalf("relu : %v %v", d, err)
	}
	if err := c.Delete(ctx, "cubbyhole/clotr/a b"); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, "cubbyhole/clotr/a b"); err != nil {
		t.Fatalf("suppression d'un absent : %v", err)
	}
	c.Token = "bad"
	if _, err := c.ReadData(ctx, "cubbyhole/clotr/x"); err == nil {
		t.Fatal("refus non signalé")
	}
}
