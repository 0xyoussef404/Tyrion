package active

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0xyoussef404/tyrion/internal/httpx"
)

func TestCheckCORSReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o) // reflects -> bad
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	res := CheckCORS(httpx.New(0, 5*time.Second), srv.URL)
	if !res.Vulnerable {
		t.Fatalf("expected CORS vuln, got %+v", res)
	}
}

func TestCheckCORSSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	if CheckCORS(httpx.New(0, 5*time.Second), srv.URL).Vulnerable {
		t.Fatal("static allow-list origin should not be flagged")
	}
}

func TestBypass(t *testing.T) {
	// 403 on /admin, but 200 on /admin/ (trailing slash bypass).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(403)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/admin") {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	hits := RunBypass(httpx.New(0, 5*time.Second), srv.URL+"/admin", 403)
	if len(hits) == 0 {
		t.Fatal("expected at least one bypass hit")
	}
}

func TestMissingSecurityHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-Frame-Options", "DENY")
	missing := MissingSecurityHeaders(h)
	if len(missing) == 0 {
		t.Fatal("expected missing headers")
	}
	for _, m := range missing {
		if m == "X-Frame-Options" {
			t.Fatal("X-Frame-Options is present, should not be reported missing")
		}
	}
}
