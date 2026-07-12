package intel

import (
	"net/url"
	"sort"
)

// ParamStat is a parameter and how often it was seen.
type ParamStat struct {
	Name  string
	Count int
}

// MineParams collects query parameters across URLs, ranked by frequency — a
// ready-made wordlist for parameter fuzzing.
func MineParams(urls []string) []ParamStat {
	counts := map[string]int{}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		for k := range u.Query() {
			counts[k]++
		}
	}
	out := make([]ParamStat, 0, len(counts))
	for k, c := range counts {
		out = append(out, ParamStat{Name: k, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Name < out[j].Name
		}
		return out[i].Count > out[j].Count
	})
	return out
}
