package intel

import "testing"

func TestExtractSecrets(t *testing.T) {
	src := `
		const AWS = "AKIAIOSFODNN7EXAMPLE";
		const stripe = "sk_live_abcdef0123456789abcd";
		const gh = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB";
		const okKey = "sk_test_shouldbelowerconfidence1234";
	`
	secrets := ExtractSecrets("app.js", src)
	types := map[string]int{}
	for _, s := range secrets {
		types[s.Type] = s.Confidence
	}
	if _, ok := types["stripe_live"]; !ok {
		t.Error("missed stripe_live")
	}
	if _, ok := types["github_token"]; !ok {
		t.Error("missed github_token")
	}
	// AKIA...EXAMPLE is denylisted ("example") -> should be filtered out.
	if _, ok := types["aws_access_key"]; ok {
		t.Error("example AWS key should be denylisted")
	}
	if types["stripe_live"] <= types["stripe_test"] {
		t.Error("live key should outrank test key")
	}
	// Ensure values are masked, not raw.
	for _, s := range secrets {
		if len(s.Value) > 4 && s.Value[:4] == "sk_l" && !contains(s.Value, "…") {
			t.Errorf("secret not masked: %s", s.Value)
		}
	}
}

func TestAnalyzeJS(t *testing.T) {
	src := `
		const base = {apiUrl: "https://api.target.com/v2"};
		fetch("/api/users/123");
		axios.post("/api/admin/createUser", data);
		const img = "/static/logo.png";
		fetch("https://cdn.target.com/app.js");
	`
	a := AnalyzeJS("main.js", src)
	if !hasStr(a.Endpoints, "/api/users/123") {
		t.Errorf("missed /api/users/123: %v", a.Endpoints)
	}
	if !hasStr(a.Endpoints, "/api/admin/createUser") {
		t.Errorf("missed admin endpoint: %v", a.Endpoints)
	}
	if hasStr(a.Endpoints, "/static/logo.png") {
		t.Error("static asset should be filtered from endpoints")
	}
	if !hasStr(a.APIBases, "https://api.target.com/v2") {
		t.Errorf("missed api base: %v", a.APIBases)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
func hasStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
