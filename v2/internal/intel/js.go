package intel

import (
	"regexp"
	"sort"
	"strings"

	"github.com/0xyoussef404/tyrion/internal/model"
)

var (
	reAbsURL  = regexp.MustCompile(`https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{4,}`)
	reRelPath = regexp.MustCompile(`["'` + "`" + `](/[a-zA-Z0-9_\-./]{2,}(?:\?[a-zA-Z0-9_\-=&%]*)?)["'` + "`" + `]`)
	reFetch   = regexp.MustCompile(`(?:fetch|axios(?:\.\w+)?|\.(?:get|post|put|delete|patch)|url\s*:)\s*\(?\s*["'` + "`" + `]([^"'` + "`" + `]{2,})["'` + "`" + `]`)
	reAPIBase = regexp.MustCompile(`(?i)(?:baseurl|apiurl|api_base|api_url|endpoint|host)\s*[:=]\s*["'` + "`" + `]([^"'` + "`" + `]{4,})["'` + "`" + `]`)
	reGraphQL = regexp.MustCompile(`(?i)(query|mutation|subscription)\s+\w+\s*[({]`)
)

// JSAnalysis holds everything extracted from a JS bundle.
type JSAnalysis struct {
	Endpoints  []string
	URLs       []string
	APIBases   []string
	Secrets    []*model.Secret
	HasGraphQL bool
}

// AnalyzeJS extracts endpoints, URLs, API bases, secrets and GraphQL hints from
// a JavaScript source string.
func AnalyzeJS(location, content string) JSAnalysis {
	a := JSAnalysis{}
	urls := map[string]bool{}
	eps := map[string]bool{}
	bases := map[string]bool{}

	for _, m := range reAbsURL.FindAllString(content, -1) {
		urls[cleanURL(m)] = true
	}
	for _, m := range reRelPath.FindAllStringSubmatch(content, -1) {
		if p := m[1]; looksLikeEndpoint(p) {
			eps[p] = true
		}
	}
	for _, m := range reFetch.FindAllStringSubmatch(content, -1) {
		v := m[1]
		if strings.HasPrefix(v, "http") {
			urls[cleanURL(v)] = true
		} else if strings.HasPrefix(v, "/") && looksLikeEndpoint(v) {
			eps[v] = true
		}
	}
	for _, m := range reAPIBase.FindAllStringSubmatch(content, -1) {
		bases[strings.TrimRight(m[1], "/")] = true
	}
	a.HasGraphQL = reGraphQL.MatchString(content)
	a.Secrets = ExtractSecrets(location, content)

	a.URLs = keys(urls)
	a.Endpoints = keys(eps)
	a.APIBases = keys(bases)
	return a
}

func looksLikeEndpoint(p string) bool {
	// Skip static asset paths and image data.
	low := strings.ToLower(p)
	for _, ext := range []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".ico", ".map", ".webp"} {
		if strings.HasSuffix(low, ext) {
			return false
		}
	}
	// Must contain a meaningful segment.
	return strings.Count(p, "/") >= 1 && len(p) >= 3
}

func cleanURL(u string) string {
	return strings.TrimRight(u, `"'`+"`),;")
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
