package intel

import (
	"sort"
	"strings"

	"github.com/0xyoussef404/tyrion/internal/model"
)

// Cluster is a group of hosts that share an infrastructure signal.
type Cluster struct {
	Signal string // favicon:<hash> | cert:<hash>
	Hosts  []string
}

// Correlate finds hosts sharing a favicon hash or TLS certificate — a strong
// hint of related / hidden infrastructure — and returns clusters + graph edges.
func Correlate(services []*model.HTTPService) ([]Cluster, []*model.Edge) {
	byFav := map[string][]string{}
	byCert := map[string][]string{}
	for _, s := range services {
		if s.FaviconHash != "" {
			byFav[s.FaviconHash] = append(byFav[s.FaviconHash], s.Host)
		}
		if s.TLSCertHash != "" {
			byCert[s.TLSCertHash] = append(byCert[s.TLSCertHash], s.Host)
		}
	}
	var clusters []Cluster
	var edges []*model.Edge
	emit := func(prefix, rel string, groups map[string][]string) {
		keys := make([]string, 0, len(groups))
		for k := range groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			hosts := model.SortedUnique(groups[k])
			if len(hosts) < 2 {
				continue
			}
			clusters = append(clusters, Cluster{Signal: prefix + ":" + k, Hosts: hosts})
			for i := 0; i < len(hosts); i++ {
				for j := i + 1; j < len(hosts); j++ {
					edges = append(edges, &model.Edge{
						ID:   model.ID(hosts[i], rel, hosts[j]),
						From: hosts[i], Rel: rel, To: hosts[j],
					})
				}
			}
		}
	}
	emit("favicon", model.RelSharesFavicon, byFav)
	emit("cert", model.RelSharesCert, byCert)
	return clusters, edges
}

// FindingFingerprint produces a stable identity for a finding so duplicates
// collapse. Same class + same normalized route + same auth boundary = same bug.
func FindingFingerprint(class, template, authBoundary, objectType string) string {
	return model.ID(
		strings.ToLower(class),
		strings.ToLower(template),
		strings.ToLower(authBoundary),
		strings.ToLower(objectType),
	)
}

// Similarity is a 0..1 token Jaccard similarity between two finding summaries,
// used to surface near-duplicates ("74% similar to FIND-019").
func Similarity(a, b string) float64 {
	ta, tb := tokenSet(a), tokenSet(b)
	if len(ta) == 0 || len(tb) == 0 {
		return 0
	}
	inter := 0
	for t := range ta {
		if tb[t] {
			inter++
		}
	}
	union := len(ta) + len(tb) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func tokenSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, t := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	}) {
		if len(t) > 2 {
			out[t] = true
		}
	}
	return out
}
