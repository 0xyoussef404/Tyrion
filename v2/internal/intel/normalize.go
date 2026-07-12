// Package intel is the intelligence layer: it turns raw recon data into ranked,
// deduplicated, correlated signal. normalize.go collapses concrete URLs into
// route templates by detecting the type of each variable path segment.
package intel

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	reInt     = regexp.MustCompile(`^\d+$`)
	reUUID    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reMongo   = regexp.MustCompile(`^[0-9a-fA-F]{24}$`)
	reHexHash = regexp.MustCompile(`^[0-9a-fA-F]{32,64}$`)
	reEmail   = regexp.MustCompile(`^[^@\s/]+@[^@\s/]+\.[a-zA-Z]{2,}$`)
	reDate    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	reJWT     = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
	reB64     = regexp.MustCompile(`^[A-Za-z0-9+/]{16,}={0,2}$`)
	reSlug    = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+){2,}$`)
)

// Normalized is the result of normalizing a URL.
type Normalized struct {
	Template string // /api/users/{integer}
	Path     string // original path
	Host     string
	Params   []string
	VarTypes []string // types encountered, e.g. [integer uuid]
}

// Normalize parses a raw URL and returns its route template.
func Normalize(raw string) Normalized {
	u, err := url.Parse(raw)
	n := Normalized{}
	if err != nil || u.Path == "" {
		n.Template = raw
		n.Path = raw
		return n
	}
	n.Host = u.Host
	n.Path = u.Path
	for k := range u.Query() {
		n.Params = append(n.Params, k)
	}

	segs := strings.Split(u.Path, "/")
	types := map[string]bool{}
	for i, s := range segs {
		if s == "" {
			continue
		}
		if t := classify(s); t != "" {
			segs[i] = "{" + t + "}"
			types[t] = true
		}
	}
	n.Template = strings.Join(segs, "/")
	if n.Template == "" {
		n.Template = "/"
	}
	if u.Host != "" {
		n.Template = u.Host + n.Template
	}
	for t := range types {
		n.VarTypes = append(n.VarTypes, t)
	}
	return n
}

// classify returns the variable type of a path segment, or "" if it is static.
func classify(s string) string {
	switch {
	case reInt.MatchString(s):
		return "integer"
	case reUUID.MatchString(s):
		return "uuid"
	case reJWT.MatchString(s):
		return "jwt"
	case reMongo.MatchString(s):
		return "mongoid"
	case reHexHash.MatchString(s):
		return "hash"
	case reEmail.MatchString(s):
		return "email"
	case reDate.MatchString(s):
		return "date"
	case reSlug.MatchString(s):
		return "slug"
	case reB64.MatchString(s) && strings.ContainsAny(s, "+/="):
		return "base64"
	}
	return ""
}

// IsIDORCandidate reports whether a normalized route looks like an object-id
// lookup worth testing for IDOR/BOLA.
func (n Normalized) IsIDORCandidate() bool {
	for _, t := range n.VarTypes {
		switch t {
		case "integer", "uuid", "mongoid", "hash":
			return true
		}
	}
	return false
}
