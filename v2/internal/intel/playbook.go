package intel

import (
	"sort"
	"strings"
)

// techPlaybooks maps a detected technology to concrete attack paths worth
// trying — turning fingerprints into next actions.
var techPlaybooks = map[string][]string{
	"spring":     {"/actuator, /actuator/env, /actuator/heapdump (Spring Boot actuator exposure)", "Spring4Shell (CVE-2022-22965) on Tomcat", "SpEL injection in error pages"},
	"tomcat":     {"/manager/html default creds (tomcat:tomcat)", "PUT-based JSP upload if WebDAV enabled", "AJP Ghostcat (CVE-2020-1938)"},
	"jenkins":    {"/script Groovy console (unauth RCE)", "/asynchPeople, /whoAmI info leak", "CVE-2024-23897 arbitrary file read"},
	"gitlab":     {"Registration open -> internal projects", "GraphQL introspection for users", "SSRF via webhook/import URLs"},
	"grafana":    {"CVE-2021-43798 path traversal (/public/plugins/../..)", "Default admin:admin", "Snapshot public exposure"},
	"kibana":     {"CVE-2019-7609 (Timelion) RCE", "Console for Elasticsearch queries", "Unauth dashboard access"},
	"wordpress":  {"/wp-json/wp/v2/users user enum", "xmlrpc.php amplification/bruteforce", "Vulnerable plugin scan"},
	"drupal":     {"Drupalgeddon2 (CVE-2018-7600)", "/user/register open registration", "REST API exposure"},
	"jira":       {"CVE-2019-11581 SSRF/RCE", "/rest/api/2/user/picker enum", "Public dashboards/filters"},
	"confluence": {"CVE-2022-26134 OGNL RCE", "CVE-2023-22515 broken access control", "Anonymous space access"},
	"nginx":      {"Alias traversal (location misconfig)", "Merge slashes/off-by-slash", "Missing security headers"},
	"apache":     {"CVE-2021-41773 path traversal", "mod_status /server-status", ".htaccess/.htpasswd exposure"},
	"iis":        {"Tilde (~) short-name enumeration", "trace.axd/elmah.axd", "WebDAV methods"},
	"laravel":    {".env exposure", "APP_DEBUG=true stacktrace + Ignition RCE (CVE-2021-3129)", "/telescope, /horizon"},
	"django":     {"DEBUG=True settings leak", "/admin default", "Weak SECRET_KEY -> session forgery"},
	"graphql":    {"Introspection query", "Batching/aliasing for brute-force", "Field suggestions for schema recovery"},
	"aws":        {"S3 bucket ACL/policy checks", "IMDS via SSRF (169.254.169.254)", "Public Lambda function URLs"},
	"azure":      {"Storage blob container listing", "Managed identity via SSRF", "App Service SCM (/.scm) access"},
	"firebase":   {"Open Firestore/RTDB read/write rules", ".json REST endpoint on *.firebaseio.com", "Public storage buckets"},
}

// PlaybookFor returns attack suggestions for a set of detected technologies.
func PlaybookFor(techs []string) map[string][]string {
	out := map[string][]string{}
	for _, t := range techs {
		tl := strings.ToLower(t)
		for key, plays := range techPlaybooks {
			if strings.Contains(tl, key) {
				out[key] = plays
			}
		}
	}
	return out
}

// KnownTech lists the technologies with playbooks (for docs/help).
func KnownTech() []string {
	out := make([]string, 0, len(techPlaybooks))
	for k := range techPlaybooks {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
