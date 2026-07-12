package intel

import "testing"

func TestClassifyURL(t *testing.T) {
	if cs := ClassifyURL("https://x.com/p?url=http://evil"); !has(cs, ClassSSRF) || !has(cs, ClassRedirect) {
		t.Errorf("url= param should flag ssrf+redirect: %v", cs)
	}
	if cs := ClassifyURL("https://x.com/search?q=test"); !has(cs, ClassXSS) {
		t.Errorf("q= should flag xss: %v", cs)
	}
	if cs := ClassifyURL("https://x.com/item?file=/etc/passwd"); !has(cs, ClassLFI) {
		t.Errorf("file= should flag lfi: %v", cs)
	}
	if cs := ClassifyURL("https://x.com/api/orders/1234"); !has(cs, ClassIDOR) {
		t.Errorf("numeric path id should flag idor: %v", cs)
	}
}

func TestJuicyCategories(t *testing.T) {
	if c := JuicyCategories("https://x.com/.git/config"); !has(c, "vcs") || !has(c, "config") {
		t.Errorf("expected vcs+config: %v", c)
	}
	if c := JuicyCategories("https://x.com/backup/db.sql.bak"); !has(c, "backup") {
		t.Errorf("expected backup: %v", c)
	}
	if c := JuicyCategories("https://x.com/api/v2/users"); !has(c, "api") {
		t.Errorf("expected api: %v", c)
	}
}

func TestMineParams(t *testing.T) {
	urls := []string{"https://x.com/a?id=1&q=x", "https://x.com/b?id=2", "https://x.com/c?q=y"}
	ps := MineParams(urls)
	if len(ps) != 2 || ps[0].Name != "id" || ps[0].Count != 2 {
		t.Fatalf("param mining wrong: %+v", ps)
	}
}

func TestDorks(t *testing.T) {
	d := Dorks("example.com")
	if len(d["google"]) == 0 || len(d["github"]) == 0 || len(d["shodan"]) == 0 {
		t.Fatalf("dorks incomplete: %+v", d)
	}
	if q := FaviconShodanQuery("116323821"); q != "http.favicon.hash:116323821" {
		t.Errorf("favicon query wrong: %q", q)
	}
}

func TestPlaybook(t *testing.T) {
	p := PlaybookFor([]string{"Spring Boot", "nginx"})
	if len(p["spring"]) == 0 || len(p["nginx"]) == 0 {
		t.Fatalf("playbook missing: %+v", p)
	}
}

func has(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
