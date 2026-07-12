package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/0xyoussef404/tyrion/internal/httpx"
	"github.com/0xyoussef404/tyrion/internal/model"
)

// A server that (buggily) returns the admin body to ANYONE — a missing-authz bug.
func TestCompareDetectsMissingAuthz(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"success":true,"role":"admin"}`))
	}))
	defer srv.Close()

	ids := []*model.Identity{
		{Name: "anonymous", Privilege: 0},
		{Name: "admin", Privilege: 100, Headers: map[string]string{"Authorization": "Bearer x"}},
	}
	client := httpx.New(0, 5*time.Second)
	rep, err := Compare(client, Request{Method: "POST", URL: srv.URL + "/api/role/addRole"}, ids)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != "potential-bfla" {
		t.Fatalf("verdict=%q want potential-bfla (results: %+v)", rep.Verdict, rep.Results)
	}
	if rep.Confidence < 80 {
		t.Errorf("confidence=%d, expected high for identical admin body", rep.Confidence)
	}
}

// A properly-guarded endpoint: anonymous gets 401, admin gets 200 -> no finding.
func TestCompareRespectsProperAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()

	ids := []*model.Identity{
		{Name: "anonymous", Privilege: 0},
		{Name: "admin", Privilege: 100, Headers: map[string]string{"Authorization": "Bearer x"}},
	}
	client := httpx.New(0, 5*time.Second)
	rep, _ := Compare(client, Request{Method: "POST", URL: srv.URL + "/api/role/addRole"}, ids)
	if rep.Verdict != "ok" {
		t.Fatalf("verdict=%q want ok", rep.Verdict)
	}
}
