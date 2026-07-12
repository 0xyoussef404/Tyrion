// Package config defines scan profiles: named bundles of pipeline stages so a
// user picks one profile instead of a dozen flags.
package config

// Profile is an ordered set of stage IDs to run.
type Profile struct {
	Name        string
	Description string
	Stages      []string
}

// Stage IDs known to the pipeline. Keeping them as constants avoids typos
// between the profile table and the pipeline builder.
const (
	StageSubEnum     = "subdomain-enum"
	StageDNSResolve  = "dns-resolve"
	StageHTTPProbe   = "http-probe"
	StagePortScan    = "port-scan"
	StageASN         = "asn-map"
	StageCrawl       = "crawl"
	StageArchives    = "archive-urls"
	StageJS          = "js-analysis"
	StageNuclei      = "nuclei"
	StageTakeover    = "takeover"
	StageSwagger     = "swagger"
	StageGraphQL     = "graphql"
	StageScreens     = "screenshots"
	StageNormalize   = "normalize" // intelligence: endpoint normalization
	StageScore       = "score"     // intelligence: scoring
	StageGraph       = "correlate" // intelligence: asset graph
	StageAuthSurface = "auth-surface"
	StageReport      = "report"
)

// Profiles is the built-in catalogue.
var Profiles = map[string]Profile{
	"passive": {
		Name: "passive", Description: "Passive enum + DNS + HTTP + intelligence, no active probing",
		Stages: []string{StageSubEnum, StageDNSResolve, StageHTTPProbe, StageArchives, StageJS,
			StageAuthSurface, StageNormalize, StageScore, StageGraph, StageReport},
	},
	"fast": {
		Name: "fast", Description: "Passive + crawl + JS + light nuclei",
		Stages: []string{StageSubEnum, StageDNSResolve, StageHTTPProbe, StageCrawl, StageArchives,
			StageJS, StageAuthSurface, StageNormalize, StageScore, StageGraph, StageReport},
	},
	"deep": {
		Name: "deep", Description: "Everything: active scanning + full intelligence",
		Stages: []string{StageSubEnum, StageDNSResolve, StageASN, StageHTTPProbe, StagePortScanID(),
			StageCrawl, StageArchives, StageJS, StageSwagger, StageGraphQL, StageNuclei, StageTakeover,
			StageScreens, StageAuthSurface, StageNormalize, StageScore, StageGraph, StageReport},
	},
	"api": {
		Name: "api", Description: "API-focused: swagger + graphql + JS APIs",
		Stages: []string{StageSubEnum, StageDNSResolve, StageHTTPProbe, StageCrawl, StageJS,
			StageSwagger, StageGraphQL, StageAuthSurface, StageNormalize, StageScore, StageReport},
	},
	"infra": {
		Name: "infra", Description: "Infrastructure: ASN + ports + takeover",
		Stages: []string{StageSubEnum, StageDNSResolve, StageASN, StagePortScanID(), StageHTTPProbe,
			StageTakeover, StageScore, StageGraph, StageReport},
	},
	"continuous": {
		Name: "continuous", Description: "Lean re-runnable set for monitoring (incremental diff)",
		Stages: []string{StageSubEnum, StageDNSResolve, StageHTTPProbe, StageArchives, StageJS,
			StageNormalize, StageScore, StageReport},
	},
}

// StagePortScanID returns the port-scan stage id (helper to keep var block tidy).
func StagePortScanID() string { return StagePortScan }

// Get returns a profile by name.
func Get(name string) (Profile, bool) {
	p, ok := Profiles[name]
	return p, ok
}

// Names lists profile names.
func Names() []string {
	return []string{"passive", "fast", "deep", "api", "infra", "continuous"}
}
