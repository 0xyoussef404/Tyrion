// Package scope decides whether a discovered host/URL is in scope. It supports
// wildcard include/exclude rules so the pipeline never wanders outside the
// engagement boundary.
package scope

import (
	"bufio"
	"os"
	"strings"
)

// Scope holds include and exclude patterns.
type Scope struct {
	Include []string
	Exclude []string
}

// New builds a scope from a root domain (implicit *.root include).
func New(root string) *Scope {
	root = strings.TrimPrefix(strings.ToLower(root), "*.")
	return &Scope{Include: []string{root, "*." + root}}
}

// LoadFile reads a scope file: lines beginning with "!" are exclusions.
func LoadFile(path string) (*Scope, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	s := &Scope{}
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "!") {
			s.Exclude = append(s.Exclude, strings.ToLower(line[1:]))
		} else {
			s.Include = append(s.Include, strings.ToLower(line))
		}
	}
	return s, sc.Err()
}

// AddInclude / AddExclude extend the scope.
func (s *Scope) AddInclude(p string) { s.Include = append(s.Include, strings.ToLower(p)) }
func (s *Scope) AddExclude(p string) { s.Exclude = append(s.Exclude, strings.ToLower(p)) }

// Allows reports whether host is in scope.
func (s *Scope) Allows(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	// strip scheme / path / port if a URL slipped in
	host = hostOnly(host)
	for _, ex := range s.Exclude {
		if match(ex, host) {
			return false
		}
	}
	if len(s.Include) == 0 {
		return true
	}
	for _, in := range s.Include {
		if match(in, host) {
			return true
		}
	}
	return false
}

// Filter returns only the in-scope hosts.
func (s *Scope) Filter(hosts []string) []string {
	out := hosts[:0:0]
	for _, h := range hosts {
		if s.Allows(h) {
			out = append(out, h)
		}
	}
	return out
}

func hostOnly(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s[i:], "]") {
		s = s[:i]
	}
	return s
}

// match supports a leading "*." wildcard and exact matches.
func match(pattern, host string) bool {
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:]
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return false
}
