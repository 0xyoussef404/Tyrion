// Package model defines the core entities of the Tyrion platform. Every recon
// artifact is a typed record with a stable ID so it can be stored, queried,
// correlated, and diffed across scans (incremental recon).
package model

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// Entity kinds. These double as store "table" names.
const (
	KindProject     = "projects"
	KindScope       = "scopes"
	KindAsset       = "assets"
	KindHTTPService = "http_services"
	KindURL         = "urls"
	KindEndpoint    = "endpoints"
	KindParameter   = "parameters"
	KindJSFile      = "javascript_files"
	KindSecret      = "secrets"
	KindPort        = "ports"
	KindScanRun     = "scan_runs"
	KindToolRun     = "tool_runs"
	KindFinding     = "findings"
	KindEvidence    = "evidence"
	KindIdentity    = "identities"
	KindEdge        = "edges"
)

// Record is the common envelope every entity satisfies for the store.
type Record interface {
	RecordKind() string
	RecordID() string
}

// Project is a target engagement.
type Project struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Root      string    `json:"root"` // primary domain
	CreatedAt time.Time `json:"created_at"`
	Tags      []string  `json:"tags,omitempty"`
}

func (p *Project) RecordKind() string { return KindProject }
func (p *Project) RecordID() string   { return p.ID }

// Asset is a host / subdomain and its resolved facts.
type Asset struct {
	ID          string    `json:"id"`
	Host        string    `json:"host"`
	IPs         []string  `json:"ips,omitempty"`
	CNAME       string    `json:"cname,omitempty"`
	ASN         string    `json:"asn,omitempty"`
	CDN         string    `json:"cdn,omitempty"`
	Source      string    `json:"source,omitempty"` // which tool found it
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Alive       bool      `json:"alive"`
	Fingerprint string    `json:"fingerprint,omitempty"` // for incremental recon
}

func (a *Asset) RecordKind() string { return KindAsset }
func (a *Asset) RecordID() string   { return a.ID }

// HTTPService is a live HTTP(S) endpoint on a host.
type HTTPService struct {
	ID          string   `json:"id"`
	Host        string   `json:"host"`
	URL         string   `json:"url"`
	Status      int      `json:"status"`
	Title       string   `json:"title,omitempty"`
	Server      string   `json:"server,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
	Length      int      `json:"length,omitempty"`
	Tech        []string `json:"tech,omitempty"`
	FaviconHash string   `json:"favicon_hash,omitempty"`
	TLSCertHash string   `json:"tls_cert_hash,omitempty"`
	BodyHash    string   `json:"body_hash,omitempty"`
}

func (h *HTTPService) RecordKind() string { return KindHTTPService }
func (h *HTTPService) RecordID() string   { return h.ID }

// URL is a discovered URL, with its normalized template form.
type URL struct {
	ID          string   `json:"id"`
	Raw         string   `json:"raw"`
	Host        string   `json:"host"`
	Path        string   `json:"path"`
	Template    string   `json:"template"` // normalized: /api/users/{integer}
	Method      string   `json:"method,omitempty"`
	Params      []string `json:"params,omitempty"`
	Status      int      `json:"status,omitempty"`
	Source      string   `json:"source,omitempty"`
	Score       int      `json:"score,omitempty"`
	AuthSurface bool     `json:"auth_surface,omitempty"`
}

func (u *URL) RecordKind() string { return KindURL }
func (u *URL) RecordID() string   { return u.ID }

// Endpoint is a deduplicated, normalized route (many URLs collapse into one).
type Endpoint struct {
	ID        string   `json:"id"`
	Template  string   `json:"template"`
	Methods   []string `json:"methods,omitempty"`
	Params    []string `json:"params,omitempty"`
	VarTypes  []string `json:"var_types,omitempty"` // integer, uuid, ...
	Count     int      `json:"count"`
	Score     int      `json:"score"`
	Sensitive bool     `json:"sensitive"`
	IDORCand  bool     `json:"idor_candidate,omitempty"`
	Source    string   `json:"source,omitempty"`
}

func (e *Endpoint) RecordKind() string { return KindEndpoint }
func (e *Endpoint) RecordID() string   { return e.ID }

// Secret is a discovered credential/token with a confidence score.
type Secret struct {
	ID         string `json:"id"`
	Type       string `json:"type"`  // aws_key, jwt, stripe, ...
	Value      string `json:"value"` // stored redacted
	Location   string `json:"location"`
	Confidence int    `json:"confidence"`
}

func (s *Secret) RecordKind() string { return KindSecret }
func (s *Secret) RecordID() string   { return s.ID }

// Identity is an authenticated persona used by the authorization comparator.
type Identity struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"` // anonymous, admin, ...
	Headers   map[string]string `json:"headers,omitempty"`
	Cookies   map[string]string `json:"cookies,omitempty"`
	Privilege int               `json:"privilege"` // 0=anon .. 100=admin
}

func (i *Identity) RecordKind() string { return KindIdentity }
func (i *Identity) RecordID() string   { return i.ID }

// Finding is a confirmed or candidate issue.
type Finding struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Class       string    `json:"class"` // bfla, idor, ssrf, ...
	Severity    string    `json:"severity"`
	Confidence  int       `json:"confidence"`
	Score       int       `json:"score"`
	Target      string    `json:"target"`
	Status      string    `json:"status"` // candidate, confirmed, duplicate
	Fingerprint string    `json:"fingerprint"`
	DuplicateOf string    `json:"duplicate_of,omitempty"`
	Summary     string    `json:"summary,omitempty"`
	EvidenceIDs []string  `json:"evidence_ids,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

func (f *Finding) RecordKind() string { return KindFinding }
func (f *Finding) RecordID() string   { return f.ID }

// Evidence captures raw request/response context for a finding.
type Evidence struct {
	ID        string    `json:"id"`
	FindingID string    `json:"finding_id"`
	Identity  string    `json:"identity,omitempty"`
	Request   string    `json:"request"`
	Response  string    `json:"response"`
	Status    int       `json:"status"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (e *Evidence) RecordKind() string { return KindEvidence }
func (e *Evidence) RecordID() string   { return e.ID }

// ScanRun records one execution of the pipeline.
type ScanRun struct {
	ID        string        `json:"id"`
	Profile   string        `json:"profile"`
	StartedAt time.Time     `json:"started_at"`
	EndedAt   time.Time     `json:"ended_at,omitempty"`
	Duration  time.Duration `json:"duration,omitempty"`
	Tasks     int           `json:"tasks"`
	OK        int           `json:"ok"`
	Failed    int           `json:"failed"`
	Cached    int           `json:"cached"`
}

func (s *ScanRun) RecordKind() string { return KindScanRun }
func (s *ScanRun) RecordID() string   { return s.ID }

// ToolRun records one subprocess execution.
type ToolRun struct {
	ID       string        `json:"id"`
	Tool     string        `json:"tool"`
	Args     []string      `json:"args,omitempty"`
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration"`
	TimedOut bool          `json:"timed_out"`
	Lines    int           `json:"lines"`
	At       time.Time     `json:"at"`
}

func (t *ToolRun) RecordKind() string { return KindToolRun }
func (t *ToolRun) RecordID() string   { return t.ID }

// Edge is a relationship in the asset graph (HOST_RESOLVES_TO_IP, etc).
type Edge struct {
	ID   string `json:"id"`
	From string `json:"from"`
	Rel  string `json:"rel"`
	To   string `json:"to"`
}

func (e *Edge) RecordKind() string { return KindEdge }
func (e *Edge) RecordID() string   { return e.ID }

// Edge relation constants.
const (
	RelResolvesTo     = "HOST_RESOLVES_TO_IP"
	RelUsesTech       = "HOST_USES_TECH"
	RelURLBelongsTo   = "URL_BELONGS_TO_HOST"
	RelJSReferences   = "JS_REFERENCES_ENDPOINT"
	RelSharesCert     = "HOST_SHARES_CERTIFICATE"
	RelSharesFavicon  = "HOST_SHARES_FAVICON"
	RelBehindCDN      = "HOST_BEHIND_CDN"
	RelIPBelongsToASN = "IP_BELONGS_TO_ASN"
)

// ID derives a stable, collision-resistant id from parts.
func ID(parts ...string) string {
	h := sha1.Sum([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])[:16]
}

// SortedUnique returns a sorted, de-duplicated copy of in.
func SortedUnique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
