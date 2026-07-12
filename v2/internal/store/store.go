// Package store is a self-contained, dependency-free persistence layer. Each
// entity kind is a JSONL file under the project directory; records are kept in
// memory as generic maps so they can be queried, filtered, and exported without
// a SQL engine. This is the platform's source of truth (text files become an
// export format, not the primary store).
package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/0xyoussef404/tyrion/internal/model"
)

// Store is a per-project record database.
type Store struct {
	dir  string
	mu   sync.RWMutex
	data map[string]map[string]map[string]any // kind -> id -> record
}

// Open loads (or initializes) a store rooted at dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, data: map[string]map[string]map[string]any{}}
	return s, s.load()
}

func (s *Store) load() error {
	files, _ := filepath.Glob(filepath.Join(s.dir, "*.jsonl"))
	for _, f := range files {
		kind := strings.TrimSuffix(filepath.Base(f), ".jsonl")
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		bucket := map[string]map[string]any{}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var rec map[string]any
			if json.Unmarshal([]byte(line), &rec) != nil {
				continue
			}
			if id, _ := rec["id"].(string); id != "" {
				bucket[id] = rec
			}
		}
		fh.Close()
		s.data[kind] = bucket
	}
	return nil
}

// Put inserts or updates a typed record.
func (s *Store) Put(rec model.Record) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	kind := rec.RecordKind()
	if s.data[kind] == nil {
		s.data[kind] = map[string]map[string]any{}
	}
	s.data[kind][rec.RecordID()] = m
	return nil
}

// PutMany is a convenience for bulk inserts.
func (s *Store) PutMany(recs ...model.Record) error {
	for _, r := range recs {
		if err := s.Put(r); err != nil {
			return err
		}
	}
	return nil
}

// Get returns a single record as a generic map.
func (s *Store) Get(kind, id string) (map[string]any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.data[kind][id]
	return r, ok
}

// All returns every record of a kind, sorted by id for determinism.
func (s *Store) All(kind string) []map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]map[string]any, 0, len(s.data[kind]))
	for _, r := range s.data[kind] {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		return fmt.Sprint(out[i]["id"]) < fmt.Sprint(out[j]["id"])
	})
	return out
}

// Count returns the number of records of a kind.
func (s *Store) Count(kind string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data[kind])
}

// Kinds lists the non-empty kinds present.
func (s *Store) Kinds() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []string{}
	for k, b := range s.data {
		if len(b) > 0 {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Query runs a small filter DSL against a kind. Supported forms (joined by
// " and " / " or "): key=v, key!=v, key contains v, key in [a,b],
// key>n, key<n, key~=regexlike (substring, case-insensitive).
func (s *Store) Query(kind, expr string) ([]map[string]any, error) {
	pred, err := ParseQuery(expr)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for _, r := range s.All(kind) {
		if pred(r) {
			out = append(out, r)
		}
	}
	return out, nil
}

// Flush persists all kinds to disk as JSONL.
func (s *Store) Flush() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for kind, bucket := range s.data {
		path := filepath.Join(s.dir, kind+".jsonl")
		var buf strings.Builder
		ids := make([]string, 0, len(bucket))
		for id := range bucket {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			b, err := json.Marshal(bucket[id])
			if err != nil {
				continue
			}
			buf.Write(b)
			buf.WriteByte('\n')
		}
		if err := os.WriteFile(path, []byte(buf.String()), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// ---- Query DSL ----------------------------------------------------------

type predicate func(map[string]any) bool

// ParseQuery compiles a filter expression into a predicate.
func ParseQuery(expr string) (predicate, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return func(map[string]any) bool { return true }, nil
	}
	// OR has lowest precedence.
	if parts := splitTop(expr, " or "); len(parts) > 1 {
		var preds []predicate
		for _, p := range parts {
			pr, err := ParseQuery(p)
			if err != nil {
				return nil, err
			}
			preds = append(preds, pr)
		}
		return func(r map[string]any) bool {
			for _, p := range preds {
				if p(r) {
					return true
				}
			}
			return false
		}, nil
	}
	if parts := splitTop(expr, " and "); len(parts) > 1 {
		var preds []predicate
		for _, p := range parts {
			pr, err := ParseQuery(p)
			if err != nil {
				return nil, err
			}
			preds = append(preds, pr)
		}
		return func(r map[string]any) bool {
			for _, p := range preds {
				if !p(r) {
					return false
				}
			}
			return true
		}, nil
	}
	return parseClause(expr)
}

func parseClause(c string) (predicate, error) {
	c = strings.TrimSpace(c)
	switch {
	case strings.Contains(c, " contains "):
		k, v := kv(c, " contains ")
		v = strings.ToLower(unquote(v))
		return func(r map[string]any) bool {
			return strings.Contains(strings.ToLower(field(r, k)), v)
		}, nil
	case strings.Contains(c, " in "):
		k, list := kv(c, " in ")
		items := parseList(list)
		return func(r map[string]any) bool {
			fv := field(r, k)
			for _, it := range items {
				if fv == it {
					return true
				}
			}
			return false
		}, nil
	case strings.Contains(c, "!="):
		k, v := kv(c, "!=")
		v = unquote(v)
		return func(r map[string]any) bool { return field(r, k) != v }, nil
	case strings.Contains(c, ">="):
		return numClause(c, ">=")
	case strings.Contains(c, "<="):
		return numClause(c, "<=")
	case strings.Contains(c, ">"):
		return numClause(c, ">")
	case strings.Contains(c, "<"):
		return numClause(c, "<")
	case strings.Contains(c, "="):
		k, v := kv(c, "=")
		v = unquote(v)
		return func(r map[string]any) bool { return field(r, k) == v }, nil
	}
	return nil, fmt.Errorf("cannot parse clause: %q", c)
}

func numClause(c, op string) (predicate, error) {
	k, v := kv(c, op)
	n, err := strconv.ParseFloat(unquote(v), 64)
	if err != nil {
		return nil, fmt.Errorf("expected number in %q", c)
	}
	return func(r map[string]any) bool {
		fn, err := strconv.ParseFloat(field(r, k), 64)
		if err != nil {
			return false
		}
		switch op {
		case ">=":
			return fn >= n
		case "<=":
			return fn <= n
		case ">":
			return fn > n
		case "<":
			return fn < n
		}
		return false
	}, nil
}

// field renders a record value as a comparable string (handles bool/number/slice).
func field(r map[string]any, key string) string {
	v, ok := r[key]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = fmt.Sprint(e)
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprint(t)
	}
}

func kv(c, sep string) (string, string) {
	i := strings.Index(c, sep)
	return strings.TrimSpace(c[:i]), strings.TrimSpace(c[i+len(sep):])
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

func parseList(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, unquote(strings.TrimSpace(p)))
	}
	return out
}

// splitTop splits by sep but ignores separators inside [...] brackets.
func splitTop(s, sep string) []string {
	var out []string
	depth, last := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			out = append(out, s[last:i])
			last = i + len(sep)
			i += len(sep) - 1
		}
	}
	out = append(out, s[last:])
	return out
}
