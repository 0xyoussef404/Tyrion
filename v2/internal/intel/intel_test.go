package intel

import "testing"

func TestNormalizeClassify(t *testing.T) {
	cases := map[string]string{
		"https://x.com/api/users/123":                              "x.com/api/users/{integer}",
		"https://x.com/order/550e8400-e29b-41d4-a716-446655440000": "x.com/order/{uuid}",
		"https://x.com/u/507f1f77bcf86cd799439011":                 "x.com/u/{mongoid}",
		"https://x.com/static/app.js":                              "x.com/static/app.js",
	}
	for in, want := range cases {
		if got := Normalize(in).Template; got != want {
			t.Errorf("Normalize(%q)=%q want %q", in, got, want)
		}
	}
}

func TestIDORCandidate(t *testing.T) {
	if !Normalize("https://x.com/api/orders/42").IsIDORCandidate() {
		t.Error("integer id should be IDOR candidate")
	}
	if Normalize("https://x.com/about").IsIDORCandidate() {
		t.Error("static path should not be IDOR candidate")
	}
}

func TestScoreRanksAdminHigh(t *testing.T) {
	admin := ScoreEndpoint("api.x.com/api/admin/createUser", []string{"role"}, nil, 200, []string{"spring"}, true)
	blog := ScoreEndpoint("x.com/blog/hello-world", nil, nil, 200, nil, false)
	if admin.Total <= blog.Total {
		t.Errorf("admin (%d) should outscore blog (%d)", admin.Total, blog.Total)
	}
	if admin.Priority != "critical" && admin.Priority != "high" {
		t.Errorf("admin endpoint priority=%q, expected high/critical", admin.Priority)
	}
}

func TestSimilarity(t *testing.T) {
	a := "missing authorization on the createUser admin endpoint"
	b := "missing authorization admin createUser endpoint here"
	if s := Similarity(a, b); s < 0.5 {
		t.Errorf("similarity too low: %f", s)
	}
	if s := Similarity(a, "completely different unrelated text words"); s > 0.3 {
		t.Errorf("similarity too high: %f", s)
	}
}
