package intel

import (
	"net/url"
	"sort"
	"strings"
)

// Vulnerability classes a URL's parameters may expose. This is a gf-style
// classifier: it points a hunter at the URLs worth testing first.
const (
	ClassXSS      = "xss"
	ClassSQLi     = "sqli"
	ClassSSRF     = "ssrf"
	ClassLFI      = "lfi"
	ClassRedirect = "open-redirect"
	ClassRCE      = "rce"
	ClassSSTI     = "ssti"
	ClassIDOR     = "idor"
)

// paramSignals maps a vuln class to the parameter names that commonly carry it.
var paramSignals = map[string][]string{
	ClassXSS:      {"q", "s", "search", "query", "keyword", "name", "message", "comment", "title", "content", "text", "callback", "return", "redirect"},
	ClassSQLi:     {"id", "select", "where", "order", "sort", "filter", "user", "username", "email", "category", "page", "column", "field", "table", "row", "number"},
	ClassSSRF:     {"url", "uri", "path", "dest", "destination", "redirect", "next", "data", "domain", "callback", "feed", "host", "port", "to", "out", "image", "img", "target", "site", "page", "fetch", "load", "proxy", "webhook"},
	ClassLFI:      {"file", "document", "folder", "path", "pg", "style", "pdf", "template", "php_path", "include", "dir", "download", "page", "doc", "root", "conf"},
	ClassRedirect: {"url", "next", "target", "redirect", "redir", "return", "returnurl", "return_url", "goto", "dest", "destination", "continue", "redirect_uri", "callback", "out", "view", "login_url", "image_url"},
	ClassRCE:      {"cmd", "exec", "command", "run", "ping", "code", "do", "func", "arg", "option", "process", "daemon", "host", "ip", "query", "jump"},
	ClassSSTI:     {"template", "preview", "id", "view", "activity", "name", "content", "redirect"},
	ClassIDOR:     {"id", "user_id", "userid", "account", "account_id", "uuid", "number", "order_id", "invoice", "doc_id", "file_id", "profile", "uid", "pid", "gid", "key"},
}

// ClassifyURL returns the vuln classes a URL's query parameters suggest.
func ClassifyURL(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	params := map[string]bool{}
	for k := range u.Query() {
		params[strings.ToLower(k)] = true
	}
	// Path-segment object ids are IDOR candidates even without a query param.
	pathHasID := IsIDORPath(u.Path)

	set := map[string]bool{}
	for class, signals := range paramSignals {
		for _, sig := range signals {
			if params[sig] {
				set[class] = true
				break
			}
		}
	}
	if pathHasID {
		set[ClassIDOR] = true
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// IsIDORPath reports whether a path contains a numeric/uuid object id segment.
func IsIDORPath(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		switch classify(seg) {
		case "integer", "uuid", "mongoid", "hash":
			return true
		}
	}
	return false
}

// ClassifyURLs buckets many URLs by vuln class.
func ClassifyURLs(urls []string) map[string][]string {
	buckets := map[string][]string{}
	for _, u := range urls {
		for _, c := range ClassifyURL(u) {
			buckets[c] = append(buckets[c], u)
		}
	}
	for c := range buckets {
		buckets[c] = dedupSorted(buckets[c])
	}
	return buckets
}

func dedupSorted(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
