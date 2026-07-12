package authz

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/0xyoussef404/tyrion/internal/httpx"
	"github.com/0xyoussef404/tyrion/internal/model"
)

func TestVerifyStateChangeConfirmed(t *testing.T) {
	var mu sync.Mutex
	role := "user"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "POST" { // the mutation
			role = "admin"
			w.WriteHeader(200)
			w.Write([]byte(`{"ok":true}`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"role":"` + role + `"}`))
	}))
	defer srv.Close()

	client := httpx.New(0, 5*time.Second)
	id := &model.Identity{Name: "attacker", Privilege: 10}
	res := VerifyStateChange(client,
		Request{Method: "POST", URL: srv.URL + "/promote"},
		Request{Method: "GET", URL: srv.URL + "/role"},
		id)
	if !res.Changed {
		t.Fatalf("expected state change to be confirmed; before=%q after=%q", res.Before, res.After)
	}
}

func TestVerifyStateChangeNoChange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"role":"user"}`)) // never changes
	}))
	defer srv.Close()

	client := httpx.New(0, 5*time.Second)
	id := &model.Identity{Name: "attacker", Privilege: 10}
	res := VerifyStateChange(client,
		Request{Method: "POST", URL: srv.URL + "/promote"},
		Request{Method: "GET", URL: srv.URL + "/role"},
		id)
	if res.Changed {
		t.Fatal("did not expect a state change")
	}
}
