package intel

import (
	"net/url"
	"sort"
	"strings"
)

// Juicy categories flag URLs that frequently expose sensitive data or attack
// surface. This is the "grep juicy" pass from the classic tool, structured.
var juicySignals = map[string][]string{
	"config": {".env", "config", "settings", ".conf", "web.config", "appsettings", ".ini", ".yaml", ".yml", ".toml", "application.properties"},
	"backup": {".bak", ".old", ".backup", ".swp", ".save", "~", ".zip", ".tar", ".tar.gz", ".sql", ".db", ".dump", "backup"},
	"secret": {"secret", "token", "apikey", "api_key", "credentials", "passwd", "password", "private", ".pem", ".key", "id_rsa", ".p12", ".pfx"},
	"vcs":    {".git", ".svn", ".hg", ".gitignore", ".gitconfig", "/.git/", ".DS_Store"},
	"api":    {"/api/", "graphql", "swagger", "openapi", "api-docs", "/v1/", "/v2/", "/v3/", "/rest/", "wsdl", ".asmx"},
	"admin":  {"admin", "manage", "console", "dashboard", "internal", "phpmyadmin", "adminer", "wp-admin"},
	"debug":  {"debug", "trace.axd", "elmah", "actuator", "phpinfo", "server-status", "server-info", "metrics", "_profiler"},
	"upload": {"upload", "import", "attachment", "avatar", "file", "media", "/tmp/", "filemanager"},
	"docs":   {".log", "logs", "readme", "changelog", "todo", ".txt", ".md"},
}

// JuicyCategories returns the juicy categories a URL matches.
func JuicyCategories(raw string) []string {
	u, err := url.Parse(raw)
	target := raw
	if err == nil {
		target = u.Path + "?" + u.RawQuery
	}
	low := strings.ToLower(target)
	set := map[string]bool{}
	for cat, sigs := range juicySignals {
		for _, s := range sigs {
			if strings.Contains(low, s) {
				set[cat] = true
				break
			}
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// JuicyBuckets groups many URLs by juicy category.
func JuicyBuckets(urls []string) map[string][]string {
	buckets := map[string][]string{}
	for _, u := range urls {
		for _, c := range JuicyCategories(u) {
			buckets[c] = append(buckets[c], u)
		}
	}
	for c := range buckets {
		buckets[c] = dedupSorted(buckets[c])
	}
	return buckets
}
