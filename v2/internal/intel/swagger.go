package intel

import (
	"encoding/json"
	"sort"
	"strings"
)

// APIEndpoint is one operation parsed from an OpenAPI/Swagger document.
type APIEndpoint struct {
	Method     string
	Path       string
	Params     []string
	Auth       bool
	Deprecated bool
	OpID       string
}

var httpMethods = []string{"get", "post", "put", "delete", "patch", "options", "head"}

// ParseOpenAPI parses a Swagger 2.0 or OpenAPI 3.x JSON document into endpoints
// plus the server base URL. It uses only encoding/json (no external deps).
func ParseOpenAPI(data []byte) (eps []APIEndpoint, base string) {
	var doc map[string]any
	if json.Unmarshal(data, &doc) != nil {
		return nil, ""
	}
	base = openAPIBase(doc)
	paths, _ := doc["paths"].(map[string]any)
	globalAuth := hasGlobalSecurity(doc)

	for path, pv := range paths {
		ops, _ := pv.(map[string]any)
		// Path-level parameters apply to all methods.
		pathParams := paramNames(ops["parameters"])
		for _, m := range httpMethods {
			ov, ok := ops[m]
			if !ok {
				continue
			}
			op, _ := ov.(map[string]any)
			ep := APIEndpoint{
				Method:     strings.ToUpper(m),
				Path:       path,
				Params:     mergeUnique(pathParams, paramNames(op["parameters"])),
				Deprecated: boolVal(op["deprecated"]),
				OpID:       strVal(op["operationId"]),
			}
			// An explicit (even empty) security block overrides the global
			// default; an empty array means "explicitly unauthenticated".
			if secv, has := op["security"]; has {
				arr, _ := secv.([]any)
				ep.Auth = len(arr) > 0
			} else {
				ep.Auth = globalAuth
			}
			eps = append(eps, ep)
		}
	}
	sort.Slice(eps, func(i, j int) bool {
		if eps[i].Path == eps[j].Path {
			return eps[i].Method < eps[j].Method
		}
		return eps[i].Path < eps[j].Path
	})
	return eps, base
}

// Curl renders a ready-to-run curl for an endpoint.
func (e APIEndpoint) Curl(base string) string {
	url := strings.TrimRight(base, "/") + e.Path
	var b strings.Builder
	b.WriteString("curl -sk -X " + e.Method + " '" + url + "'")
	if e.Method == "POST" || e.Method == "PUT" || e.Method == "PATCH" {
		b.WriteString(" -H 'Content-Type: application/json' -d '{}'")
	}
	if e.Auth {
		b.WriteString(" -H 'Authorization: Bearer $TOKEN'")
	}
	return b.String()
}

// Unauthenticated returns endpoints with no declared security (worth probing).
func Unauthenticated(eps []APIEndpoint) []APIEndpoint {
	var out []APIEndpoint
	for _, e := range eps {
		if !e.Auth {
			out = append(out, e)
		}
	}
	return out
}

func openAPIBase(doc map[string]any) string {
	// OpenAPI 3: servers[0].url
	if servers, ok := doc["servers"].([]any); ok && len(servers) > 0 {
		if s0, ok := servers[0].(map[string]any); ok {
			if u := strVal(s0["url"]); u != "" {
				return u
			}
		}
	}
	// Swagger 2: host + basePath
	host := strVal(doc["host"])
	bp := strVal(doc["basePath"])
	if host != "" {
		scheme := "https"
		if schemes, ok := doc["schemes"].([]any); ok && len(schemes) > 0 {
			if s := strVal(schemes[0]); s != "" {
				scheme = s
			}
		}
		return scheme + "://" + host + bp
	}
	return bp
}

func hasGlobalSecurity(doc map[string]any) bool {
	if sec, ok := doc["security"].([]any); ok && len(sec) > 0 {
		return true
	}
	return false
}

func paramNames(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, p := range arr {
		if pm, ok := p.(map[string]any); ok {
			if n := strVal(pm["name"]); n != "" {
				out = append(out, n)
			}
		}
	}
	return out
}

func mergeUnique(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(a, b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func strVal(v any) string { s, _ := v.(string); return s }
func boolVal(v any) bool  { b, _ := v.(bool); return b }
