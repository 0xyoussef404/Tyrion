// Package reporting renders the store into human-readable Markdown: an
// engagement overview, ranked targets, and a findings section with evidence.
package reporting

import (
	"fmt"
	"sort"
	"strings"

	"github.com/0xyoussef404/tyrion/internal/model"
	"github.com/0xyoussef404/tyrion/internal/store"
)

// Markdown builds a full report for a project from its store.
func Markdown(st *store.Store, project string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Tyrion Report — %s\n\n", project)

	// Overview.
	b.WriteString("## Overview\n\n")
	fmt.Fprintf(&b, "- Assets: **%d**\n", st.Count(model.KindAsset))
	fmt.Fprintf(&b, "- Live HTTP services: **%d**\n", st.Count(model.KindHTTPService))
	fmt.Fprintf(&b, "- URLs: **%d**\n", st.Count(model.KindURL))
	fmt.Fprintf(&b, "- Endpoints (normalized): **%d**\n", st.Count(model.KindEndpoint))
	fmt.Fprintf(&b, "- Findings: **%d**\n", st.Count(model.KindFinding))
	b.WriteString("\n")

	// Top targets by score.
	eps := st.All(model.KindEndpoint)
	sort.Slice(eps, func(i, j int) bool { return num(eps[i]["score"]) > num(eps[j]["score"]) })
	if len(eps) > 0 {
		b.WriteString("## Top targets\n\n")
		b.WriteString("| Score | Template | Methods | IDOR? |\n|------:|----------|---------|:-----:|\n")
		for i, e := range eps {
			if i >= 25 {
				break
			}
			idor := ""
			if b2, _ := e["idor_candidate"].(bool); b2 {
				idor = "yes"
			}
			fmt.Fprintf(&b, "| %d | `%s` | %s | %s |\n",
				num(e["score"]), str(e["template"]), joinAny(e["methods"]), idor)
		}
		b.WriteString("\n")
	}

	// Findings.
	fs := st.All(model.KindFinding)
	sort.Slice(fs, func(i, j int) bool { return num(fs[i]["score"]) > num(fs[j]["score"]) })
	if len(fs) > 0 {
		b.WriteString("## Findings\n\n")
		for _, f := range fs {
			fmt.Fprintf(&b, "### [%s] %s\n\n", strings.ToUpper(str(f["severity"])), str(f["title"]))
			fmt.Fprintf(&b, "- Class: `%s`\n", str(f["class"]))
			fmt.Fprintf(&b, "- Target: `%s`\n", str(f["target"]))
			fmt.Fprintf(&b, "- Status: `%s`  ·  Confidence: **%d%%**  ·  Score: **%d**\n",
				str(f["status"]), num(f["confidence"]), num(f["score"]))
			if dup := str(f["duplicate_of"]); dup != "" {
				fmt.Fprintf(&b, "- Duplicate of: `%s`\n", dup)
			}
			if sum := str(f["summary"]); sum != "" {
				fmt.Fprintf(&b, "\n%s\n", sum)
			}
			// Attached evidence.
			for _, ev := range st.All(model.KindEvidence) {
				if str(ev["finding_id"]) != str(f["id"]) {
					continue
				}
				fmt.Fprintf(&b, "\n<details><summary>Evidence (%s, status %d)</summary>\n\n",
					str(ev["identity"]), num(ev["status"]))
				fmt.Fprintf(&b, "```http\n%s\n```\n\n```http\n%s\n```\n</details>\n",
					truncate(str(ev["request"]), 1500), truncate(str(ev["response"]), 1500))
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

// EvidencePack builds a self-contained PoC bundle (map of filename -> content)
// for one finding.
func EvidencePack(st *store.Store, findingID string) map[string]string {
	out := map[string]string{}
	f, ok := st.Get(model.KindFinding, findingID)
	if !ok {
		return out
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "# %s\n\nClass: %s\nSeverity: %s\nConfidence: %d%%\nTarget: %s\n\n%s\n",
		str(f["title"]), str(f["class"]), str(f["severity"]), num(f["confidence"]),
		str(f["target"]), str(f["summary"]))
	out["summary.md"] = sb.String()

	i := 0
	for _, ev := range st.All(model.KindEvidence) {
		if str(ev["finding_id"]) != findingID {
			continue
		}
		i++
		name := fmt.Sprintf("evidence-%d-%s", i, str(ev["identity"]))
		out[name+"-request.txt"] = str(ev["request"])
		out[name+"-response.txt"] = str(ev["response"])
	}
	return out
}

func num(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	if i, ok := v.(int); ok {
		return i
	}
	return 0
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func joinAny(v any) string {
	if arr, ok := v.([]any); ok {
		parts := make([]string, len(arr))
		for i, e := range arr {
			parts[i] = fmt.Sprint(e)
		}
		return strings.Join(parts, ", ")
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "\n... [truncated]"
	}
	return s
}
