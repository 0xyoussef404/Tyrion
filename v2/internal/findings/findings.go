// Package findings manages findings, their evidence vault, and duplicate
// detection. Evidence is redacted on the way in so secrets never sit in plain
// text inside a PoC bundle.
package findings

import (
	"encoding/json"
	"regexp"
	"time"

	"github.com/0xyoussef404/tyrion/internal/intel"
	"github.com/0xyoussef404/tyrion/internal/model"
	"github.com/0xyoussef404/tyrion/internal/store"
)

// Manager coordinates findings + evidence against the store.
type Manager struct {
	st *store.Store
}

// New returns a findings manager.
func New(st *store.Store) *Manager { return &Manager{st: st} }

// Add stores a finding, computing its fingerprint and detecting duplicates
// against existing findings. Returns the (possibly de-duplicated) finding.
func (m *Manager) Add(f *model.Finding) *model.Finding {
	if f.ID == "" {
		f.ID = model.ID(f.Class, f.Target, f.Title, time.Now().String())
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now()
	}
	if f.Fingerprint == "" {
		f.Fingerprint = intel.FindingFingerprint(f.Class, f.Target, "", "")
	}
	// Exact-fingerprint duplicate?
	for _, r := range m.st.All(model.KindFinding) {
		if fp, _ := r["fingerprint"].(string); fp == f.Fingerprint {
			if id, _ := r["id"].(string); id != "" && id != f.ID {
				f.Status = "duplicate"
				f.DuplicateOf = id
				break
			}
		}
	}
	if f.Status == "" {
		f.Status = "candidate"
	}
	_ = m.st.Put(f)
	return f
}

// AddEvidence stores redacted evidence and links it to a finding.
func (m *Manager) AddEvidence(ev *model.Evidence) *model.Evidence {
	if ev.ID == "" {
		ev.ID = model.ID(ev.FindingID, ev.Identity, time.Now().String())
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now()
	}
	ev.Request = Redact(ev.Request)
	ev.Response = Redact(ev.Response)
	_ = m.st.Put(ev)

	// Link back to the finding.
	if f, ok := m.st.Get(model.KindFinding, ev.FindingID); ok {
		ids, _ := f["evidence_ids"].([]any)
		f["evidence_ids"] = append(ids, ev.ID)
		// Re-store the raw map by wrapping in a passthrough record.
		_ = m.st.Put(&rawRecord{kind: model.KindFinding, id: ev.FindingID, data: f})
	}
	return ev
}

// SimilarFindings returns findings whose summary is >= threshold similar.
func (m *Manager) SimilarFindings(f *model.Finding, threshold float64) []Similar {
	var out []Similar
	for _, r := range m.st.All(model.KindFinding) {
		id, _ := r["id"].(string)
		if id == f.ID {
			continue
		}
		sum, _ := r["summary"].(string)
		if sim := intel.Similarity(f.Summary, sum); sim >= threshold {
			title, _ := r["title"].(string)
			out = append(out, Similar{ID: id, Title: title, Similarity: sim})
		}
	}
	return out
}

// Similar is a near-duplicate match.
type Similar struct {
	ID         string
	Title      string
	Similarity float64
}

// ---- Redaction ----------------------------------------------------------

var redactors = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._\-]+`),
	regexp.MustCompile(`(?i)(cookie:\s*).*`),
	regexp.MustCompile(`(?i)(set-cookie:\s*).*`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`), // JWT
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                                  // AWS key id
	regexp.MustCompile(`(?i)(api[_-]?key["'\s:=]+)[A-Za-z0-9._\-]{12,}`),    // api keys
	regexp.MustCompile(`sk_live_[0-9A-Za-z]{16,}`),                          // Stripe
	regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),  // emails
}

// Redact masks secrets and PII in a request/response dump.
func Redact(s string) string {
	for _, re := range redactors {
		s = re.ReplaceAllString(s, "$1[REDACTED]")
	}
	return s
}

// rawRecord lets us re-persist an already-decoded generic map.
type rawRecord struct {
	kind string
	id   string
	data map[string]any
}

func (r *rawRecord) RecordKind() string { return r.kind }
func (r *rawRecord) RecordID() string   { return r.id }

// MarshalJSON emits the underlying map so the store round-trips it faithfully.
func (r *rawRecord) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.data)
}
