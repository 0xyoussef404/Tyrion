package intel

import "testing"

func TestParseOpenAPI3(t *testing.T) {
	doc := `{
	  "openapi": "3.0.0",
	  "servers": [{"url": "https://api.x.com/v1"}],
	  "security": [{"bearer": []}],
	  "paths": {
	    "/users/{id}": {
	      "parameters": [{"name":"id","in":"path"}],
	      "get": {"operationId":"getUser"},
	      "delete": {"operationId":"delUser","security":[{"bearer":[]}]}
	    },
	    "/health": {
	      "get": {"operationId":"health","security":[]}
	    }
	  }
	}`
	eps, base := ParseOpenAPI([]byte(doc))
	if base != "https://api.x.com/v1" {
		t.Fatalf("base=%q", base)
	}
	if len(eps) != 3 {
		t.Fatalf("got %d endpoints, want 3", len(eps))
	}
	// /health explicitly declares empty security -> unauthenticated.
	un := Unauthenticated(eps)
	found := false
	for _, e := range un {
		if e.Path == "/health" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected /health to be unauthenticated: %+v", un)
	}
	// curl for a POST-like method includes a body flag.
	for _, e := range eps {
		if e.Path == "/users/{id}" && e.Method == "GET" {
			if got := e.Curl(base); got == "" {
				t.Error("empty curl")
			}
		}
	}
}

func TestParseSwagger2(t *testing.T) {
	doc := `{
	  "swagger":"2.0","host":"api.x.com","basePath":"/v2","schemes":["https"],
	  "paths":{"/ping":{"get":{"operationId":"ping"}}}
	}`
	eps, base := ParseOpenAPI([]byte(doc))
	if base != "https://api.x.com/v2" {
		t.Fatalf("base=%q", base)
	}
	if len(eps) != 1 || eps[0].Method != "GET" {
		t.Fatalf("eps=%+v", eps)
	}
}

func TestGraphQLOpClass(t *testing.T) {
	cases := map[string]string{
		"deleteUser":     "destructive",
		"refundPayment":  "financial",
		"grantAdminRole": "administrative",
		"createOrder":    "write",
		"getProfile":     "read",
	}
	for name, want := range cases {
		if got := GraphQLOpClass(name); got != want {
			t.Errorf("GraphQLOpClass(%q)=%q want %q", name, got, want)
		}
	}
}
