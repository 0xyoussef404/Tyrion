package intel

import "strings"

// Dorks generates ready-to-use search dorks for a domain across Google, GitHub,
// and Shodan — a fast way to surface extra attack surface and leaked data.
func Dorks(domain string) map[string][]string {
	d := strings.TrimPrefix(strings.ToLower(domain), "*.")
	google := []string{
		`site:` + d + ` -www`,
		`site:` + d + ` ext:php | ext:asp | ext:aspx | ext:jsp | ext:json | ext:xml`,
		`site:` + d + ` inurl:api | inurl:v1 | inurl:v2 | inurl:graphql`,
		`site:` + d + ` intitle:"index of"`,
		`site:` + d + ` ext:log | ext:sql | ext:bak | ext:old | ext:txt`,
		`site:` + d + ` inurl:login | inurl:admin | inurl:signin | inurl:portal`,
		`site:` + d + ` "api_key" | "apikey" | "client_secret" | "authorization"`,
		`site:pastebin.com "` + d + `"`,
		`site:` + d + ` inurl:redirect | inurl:url= | inurl:next=`,
		`site:trello.com "` + d + `"`,
	}
	github := []string{
		`"` + d + `" password`,
		`"` + d + `" api_key`,
		`"` + d + `" secret`,
		`"` + d + `" token`,
		`"` + d + `" aws_access_key_id`,
		`"` + d + `" filename:.env`,
		`"` + d + `" filename:config`,
		`org:` + orgGuess(d) + ` password`,
	}
	shodan := []string{
		`hostname:` + d,
		`ssl.cert.subject.cn:` + d,
		`ssl:"` + d + `"`,
		`http.title:"` + d + `"`,
	}
	return map[string][]string{"google": google, "github": github, "shodan": shodan}
}

// FaviconShodanQuery turns an mmh3 favicon hash (as produced by httpx -favicon)
// into a Shodan pivot query to find other hosts running the same app.
func FaviconShodanQuery(mmh3Hash string) string {
	if mmh3Hash == "" {
		return ""
	}
	return "http.favicon.hash:" + mmh3Hash
}

func orgGuess(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return domain
}
