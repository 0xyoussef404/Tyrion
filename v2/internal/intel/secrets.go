package intel

import (
	"regexp"
	"strings"

	"github.com/0xyoussef404/tyrion/internal/model"
)

// secretRule matches one secret type with a base confidence.
type secretRule struct {
	Type       string
	Re         *regexp.Regexp
	Confidence int
}

// High-signal secret patterns. Confidence reflects how specific the pattern is;
// generic patterns start lower and are boosted by context (see Extract).
var secretRules = []secretRule{
	{"aws_access_key", regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), 90},
	{"aws_secret_key", regexp.MustCompile(`(?i)aws_secret_access_key["'\s:=]+([A-Za-z0-9/+]{40})`), 80},
	{"gcp_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), 85},
	{"stripe_live", regexp.MustCompile(`\b(sk|rk)_live_[0-9A-Za-z]{16,}\b`), 95},
	{"stripe_test", regexp.MustCompile(`\b(sk|rk)_test_[0-9A-Za-z]{16,}\b`), 60},
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36,}\b`), 90},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z\-]{10,}\b`), 90},
	{"slack_webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/]+`), 85},
	{"google_oauth", regexp.MustCompile(`\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b`), 70},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`), 65},
	{"private_key", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`), 95},
	{"firebase_db", regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`), 55},
	{"firebase_key", regexp.MustCompile(`(?i)firebase[^"'\n]{0,40}?["']AIza[0-9A-Za-z_\-]{35}["']`), 70},
	{"mailgun_key", regexp.MustCompile(`\bkey-[0-9a-zA-Z]{32}\b`), 70},
	{"twilio_sid", regexp.MustCompile(`\bAC[a-z0-9]{32}\b`), 70},
	{"generic_secret", regexp.MustCompile(`(?i)(api[_-]?key|secret|token|passwd|password)["'\s:=]{1,4}["']([0-9A-Za-z_\-]{16,})["']`), 40},
}

// low-value hosts / placeholders that shouldn't be reported as secrets.
var secretDenylist = []string{"example", "your_", "xxxx", "placeholder", "changeme", "dummy", "test_key"}

// ExtractSecrets scans text (JS bundle, HTTP response, config) for secrets.
func ExtractSecrets(location, text string) []*model.Secret {
	var out []*model.Secret
	seen := map[string]bool{}
	for _, rule := range secretRules {
		for _, m := range rule.Re.FindAllString(text, -1) {
			val := strings.TrimSpace(m)
			if val == "" || denylisted(val) {
				continue
			}
			key := rule.Type + "|" + val
			if seen[key] {
				continue
			}
			seen[key] = true
			conf := rule.Confidence
			if strings.Contains(strings.ToLower(location), "prod") {
				conf = capAt(conf+5, 99)
			}
			out = append(out, &model.Secret{
				ID:         model.ID("secret", rule.Type, val),
				Type:       rule.Type,
				Value:      maskSecret(val),
				Location:   location,
				Confidence: conf,
			})
		}
	}
	return out
}

func denylisted(v string) bool {
	lv := strings.ToLower(v)
	for _, d := range secretDenylist {
		if strings.Contains(lv, d) {
			return true
		}
	}
	return false
}

// maskSecret keeps a short prefix so it is recognizable but not usable.
func maskSecret(v string) string {
	if len(v) <= 8 {
		return "****"
	}
	return v[:4] + "…" + v[len(v)-2:] + " (" + itoa(len(v)) + " chars)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
