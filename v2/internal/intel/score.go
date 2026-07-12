package intel

import "strings"

// Score is a 0-100 priority with an explainable component breakdown.
type Score struct {
	Total      int
	Components map[string]int
	Priority   string
}

// high-signal path keywords by category.
var (
	adminWords     = []string{"admin", "manage", "console", "dashboard", "internal", "superuser", "root"}
	apiWords       = []string{"api", "graphql", "rest", "rpc", "v1", "v2", "v3", "swagger", "openapi"}
	authWords      = []string{"login", "logout", "auth", "oauth", "token", "session", "sso", "saml", "register", "password", "reset", "mfa", "2fa", "verify"}
	actionWords    = []string{"create", "update", "delete", "remove", "add", "edit", "upload", "import", "export", "invite", "grant", "role", "permission", "approve", "transfer", "payment", "pay", "refund", "withdraw", "order", "invoice", "billing"}
	sensitiveWords = []string{"config", "debug", "backup", "dump", "secret", "key", "credential", "env", "private", ".git", "actuator", "metrics", "phpinfo"}
	riskyTech      = []string{"spring", "jenkins", "gitlab", "grafana", "kibana", "wordpress", "drupal", "struts", "tomcat", "weblogic", "citrix", "confluence", "jira"}
)

// ScoreEndpoint scores a normalized route plus context signals.
func ScoreEndpoint(template string, params []string, varTypes []string, status int, tech []string, novel bool) Score {
	low := strings.ToLower(template)
	c := map[string]int{}

	// Asset / endpoint value.
	c["asset_value"] = capAt(countHits(low, apiWords)*4+countHits(low, adminWords)*8, 20)
	// Endpoint sensitivity.
	c["sensitivity"] = capAt(countHits(low, sensitiveWords)*8+countHits(low, actionWords)*6+countHits(low, adminWords)*4, 20)
	// Auth surface.
	c["auth_surface"] = capAt(countHits(low, authWords)*5, 15)
	// Technology risk.
	techScore := 0
	for _, t := range tech {
		tl := strings.ToLower(t)
		for _, rt := range riskyTech {
			if strings.Contains(tl, rt) {
				techScore += 5
			}
		}
	}
	c["tech_risk"] = capAt(techScore, 10)
	// Historical novelty.
	if novel {
		c["novelty"] = 10
	}
	// Parameter risk.
	c["param_risk"] = capAt(len(params)*2, 10)
	// Response signals (2xx/3xx to sensitive routes matter more).
	sig := 0
	switch {
	case status >= 200 && status < 300:
		sig = 12
	case status == 401 || status == 403:
		sig = 15 // protected == interesting
	case status >= 300 && status < 400:
		sig = 8
	}
	// IDOR object-id present boosts response signal.
	for _, vt := range varTypes {
		if vt == "integer" || vt == "uuid" || vt == "mongoid" {
			sig += 3
		}
	}
	c["response_signal"] = capAt(sig, 15)

	total := 0
	for _, v := range c {
		total += v
	}
	if total > 100 {
		total = 100
	}
	return Score{Total: total, Components: c, Priority: priority(total)}
}

func priority(total int) string {
	switch {
	case total >= 70:
		return "critical"
	case total >= 50:
		return "high"
	case total >= 30:
		return "medium"
	default:
		return "low"
	}
}

// Sensitive reports whether a template is high-value regardless of numeric score.
func Sensitive(template string) bool {
	low := strings.ToLower(template)
	return countHits(low, adminWords)+countHits(low, sensitiveWords)+countHits(low, actionWords) > 0
}

func countHits(s string, words []string) int {
	n := 0
	for _, w := range words {
		if strings.Contains(s, w) {
			n++
		}
	}
	return n
}

func capAt(v, max int) int {
	if v > max {
		return max
	}
	return v
}
