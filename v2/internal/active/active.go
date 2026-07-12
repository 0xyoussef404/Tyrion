// Package active runs safe, targeted active checks through the shared HTTP
// client: CORS misconfiguration, 401/403 bypass attempts, and security-header
// analysis. These generate confirmable data/findings for bug-bounty triage.
package active

import (
	"net/http"
	"strings"

	"github.com/0xyoussef404/tyrion/internal/httpx"
)

// ---- CORS ---------------------------------------------------------------

// CORSResult reports a CORS misconfiguration test.
type CORSResult struct {
	URL        string
	Vulnerable bool
	ACAO       string
	ACAC       string
	Reason     string
}

// CheckCORS probes reflected-origin and null-origin CORS misconfigurations.
func CheckCORS(client *httpx.Client, url string) CORSResult {
	res := CORSResult{URL: url}
	evil := "https://evil-tyrion.example"
	for _, origin := range []string{evil, "null"} {
		resp, err := client.Do("GET", url, map[string]string{"Origin": origin}, nil, "cors:"+origin)
		if err != nil || resp == nil {
			continue
		}
		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")
		if acao == "" {
			continue
		}
		res.ACAO, res.ACAC = acao, acac
		reflected := acao == origin || (origin == evil && acao == evil)
		if (reflected || acao == "null") && strings.EqualFold(acac, "true") {
			res.Vulnerable = true
			res.Reason = "ACAO reflects attacker origin (" + acao + ") with credentials"
			return res
		}
		if acao == "*" && strings.EqualFold(acac, "true") {
			res.Vulnerable = true
			res.Reason = "wildcard ACAO with credentials"
			return res
		}
	}
	return res
}

// ---- 401/403 bypass -----------------------------------------------------

// BypassAttempt is one bypass technique to try against a protected URL.
type BypassAttempt struct {
	Label   string
	Method  string
	URL     string
	Headers map[string]string
}

// BypassAttempts generates path- and header-based 401/403 bypass techniques.
func BypassAttempts(rawURL string) []BypassAttempt {
	base, path := splitPath(rawURL)
	var out []BypassAttempt
	add := func(label, u string, h map[string]string) {
		out = append(out, BypassAttempt{Label: label, Method: "GET", URL: u, Headers: h})
	}
	// Path mutations.
	variants := map[string]string{
		"trailing-slash":   path + "/",
		"dot-slash":        path + "/.",
		"double-slash":     "/" + strings.TrimPrefix(path, "/") + "//",
		"encoded-dot":      path + "/%2e",
		"semicolon":        path + ";/",
		"path-param":       path + "/..;/",
		"trailing-space":   path + "%20",
		"trailing-tab":     path + "%09",
		"trailing-hash":    path + "%23",
		"uppercase":        strings.ToUpper(path),
		"trailing-dotjson": path + ".json",
	}
	for label, p := range variants {
		add("path:"+label, base+p, nil)
	}
	// Header-based (spoofing internal access).
	headers := []map[string]string{
		{"X-Forwarded-For": "127.0.0.1"},
		{"X-Forwarded-Host": "127.0.0.1"},
		{"X-Original-URL": path},
		{"X-Rewrite-URL": path},
		{"X-Custom-IP-Authorization": "127.0.0.1"},
		{"X-Originating-IP": "127.0.0.1"},
		{"X-Remote-Addr": "127.0.0.1"},
		{"X-Client-IP": "127.0.0.1"},
		{"Referer": base + path},
	}
	for _, h := range headers {
		var name string
		for k := range h {
			name = k
		}
		add("header:"+name, rawURL, h)
	}
	return out
}

// BypassResult is the outcome of testing a bypass attempt.
type BypassResult struct {
	BypassAttempt
	Status int
}

// RunBypass runs each attempt and returns those that returned a non-403/401
// success (candidate bypasses). baselineStatus is the original protected status.
func RunBypass(client *httpx.Client, rawURL string, baselineStatus int) []BypassResult {
	var hits []BypassResult
	for _, a := range BypassAttempts(rawURL) {
		resp, err := client.Do(a.Method, a.URL, a.Headers, nil, "bypass:"+a.Label)
		if err != nil || resp == nil {
			continue
		}
		if resp.Status >= 200 && resp.Status < 400 && resp.Status != baselineStatus {
			hits = append(hits, BypassResult{BypassAttempt: a, Status: resp.Status})
		}
	}
	return hits
}

// ---- Security headers ---------------------------------------------------

var importantHeaders = []string{
	"Content-Security-Policy",
	"Strict-Transport-Security",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
}

// MissingSecurityHeaders returns the important security headers absent from a
// response.
func MissingSecurityHeaders(h http.Header) []string {
	var missing []string
	for _, name := range importantHeaders {
		if h.Get(name) == "" {
			missing = append(missing, name)
		}
	}
	return missing
}

// ---- helpers ------------------------------------------------------------

func splitPath(raw string) (base, path string) {
	s := raw
	scheme := ""
	if i := strings.Index(s, "://"); i >= 0 {
		scheme = s[:i+3]
		s = s[i+3:]
	}
	host := s
	path = "/"
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		host = s[:i]
		path = s[i:]
		if q := strings.IndexAny(path, "?#"); q >= 0 {
			path = path[:q]
		}
	}
	if path == "" {
		path = "/"
	}
	return scheme + host, path
}
