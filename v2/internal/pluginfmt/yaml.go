// Package pluginfmt is a tiny, dependency-free parser for the subset of YAML
// used by Tyrion plugin definitions: comments, "key: scalar", inline lists
// "key: [a, b]", and block lists ("key:" then indented "- item"). It is not a
// general YAML parser — it is intentionally small and predictable.
package pluginfmt

import (
	"bufio"
	"fmt"
	"strings"
)

// Parse returns a map whose values are either string or []string.
func Parse(data string) (map[string]any, error) {
	out := map[string]any{}
	sc := bufio.NewScanner(strings.NewReader(data))
	var curKey string
	var curList []string
	inList := false

	flush := func() {
		if inList {
			out[curKey] = curList
			inList = false
			curList = nil
		}
	}

	line := 0
	for sc.Scan() {
		line++
		raw := sc.Text()
		trimmed := strings.TrimSpace(stripComment(raw))
		if trimmed == "" {
			continue
		}
		// Block-list item.
		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			if !inList {
				return nil, fmt.Errorf("line %d: list item without a key", line)
			}
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			curList = append(curList, unquote(item))
			continue
		}
		// key: value
		idx := strings.Index(trimmed, ":")
		if idx < 0 {
			return nil, fmt.Errorf("line %d: expected 'key: value', got %q", line, trimmed)
		}
		flush()
		key := strings.TrimSpace(trimmed[:idx])
		val := strings.TrimSpace(trimmed[idx+1:])
		switch {
		case val == "":
			// Start of a block list (or empty scalar; resolved on flush).
			curKey = key
			inList = true
			curList = nil
			out[key] = "" // default if no items follow
		case strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]"):
			out[key] = parseInlineList(val)
		default:
			out[key] = unquote(val)
		}
	}
	flush()
	return out, sc.Err()
}

func parseInlineList(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if strings.TrimSpace(s) == "" {
		return []string{}
	}
	parts := splitRespectQuotes(s)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, unquote(strings.TrimSpace(p)))
	}
	return out
}

// splitRespectQuotes splits on commas not inside quotes.
func splitRespectQuotes(s string) []string {
	var out []string
	var b strings.Builder
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
			b.WriteByte(c)
		case c == '"' || c == '\'':
			q = c
			b.WriteByte(c)
		case c == ',':
			out = append(out, b.String())
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	out = append(out, b.String())
	return out
}

func stripComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if q != 0 {
			if c == q {
				q = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			q = c
			continue
		}
		if c == '#' {
			return s[:i]
		}
	}
	return s
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// String returns a string field or a fallback.
func String(m map[string]any, key, def string) string {
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return def
}

// List returns a []string field (accepts a single scalar as a 1-element list).
func List(m map[string]any, key string) []string {
	switch v := m[key].(type) {
	case []string:
		return v
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	}
	return nil
}
