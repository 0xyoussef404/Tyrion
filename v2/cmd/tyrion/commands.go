package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0xyoussef404/tyrion/internal/authz"
	"github.com/0xyoussef404/tyrion/internal/config"
	"github.com/0xyoussef404/tyrion/internal/engine"
	"github.com/0xyoussef404/tyrion/internal/findings"
	"github.com/0xyoussef404/tyrion/internal/httpx"
	"github.com/0xyoussef404/tyrion/internal/model"
	"github.com/0xyoussef404/tyrion/internal/pipeline"
	"github.com/0xyoussef404/tyrion/internal/reporting"
	"github.com/0xyoussef404/tyrion/internal/scope"
	"github.com/0xyoussef404/tyrion/internal/store"
	"github.com/0xyoussef404/tyrion/internal/tools"
)

// query <domain> <kind> <expr...>
func cmdQuery(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: tyrion query <domain> <kind> [expr]")
	}
	domain, kind := strings.ToLower(args[0]), args[1]
	expr := strings.Join(args[2:], " ")
	st, err := store.Open(filepath.Join(".", domain, ".tyrion"))
	if err != nil {
		return err
	}
	recs, err := st.Query(kind, expr)
	if err != nil {
		return err
	}
	for _, r := range recs {
		b, _ := json.Marshal(r)
		fmt.Println(string(b))
	}
	fmt.Fprintf(os.Stderr, "\n%d %s match\n", len(recs), kind)
	return nil
}

// export <domain> <kind> [--format txt|json]
func cmdExport(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: tyrion export <domain> <kind> [--format txt|json]")
	}
	domain, kind := strings.ToLower(args[0]), args[1]
	format := "txt"
	for i := 2; i < len(args); i++ {
		if args[i] == "--format" && i+1 < len(args) {
			format = args[i+1]
		}
	}
	st, err := store.Open(filepath.Join(".", domain, ".tyrion"))
	if err != nil {
		return err
	}
	recs := st.All(kind)
	switch format {
	case "json":
		for _, r := range recs {
			b, _ := json.Marshal(r)
			fmt.Println(string(b))
		}
	default:
		// Emit the most identifying field per record.
		for _, r := range recs {
			for _, k := range []string{"url", "raw", "host", "template", "title"} {
				if v, ok := r[k].(string); ok && v != "" {
					fmt.Println(v)
					break
				}
			}
		}
	}
	return nil
}

// assets|endpoints|findings <domain>
func cmdList(args []string, kind string) error {
	domain, err := mustDomain(args)
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(".", domain, ".tyrion"))
	if err != nil {
		return err
	}
	recs := st.All(kind)
	if kind == model.KindEndpoint {
		sort.Slice(recs, func(i, j int) bool { return numField(recs[i], "score") > numField(recs[j], "score") })
	}
	for _, r := range recs {
		switch kind {
		case model.KindAsset:
			fmt.Printf("%-40s alive=%v %s\n", r["host"], r["alive"], r["source"])
		case model.KindEndpoint:
			fmt.Printf("[%3d] %-8s %s\n", numField(r, "score"), boolMark(r, "idor_candidate"), r["template"])
		case model.KindFinding:
			fmt.Printf("[%s] %-16s conf=%d%% %s\n", strings.ToUpper(strv(r, "severity")), strv(r, "class"), numField(r, "confidence"), strv(r, "title"))
		default:
			b, _ := json.Marshal(r)
			fmt.Println(string(b))
		}
	}
	fmt.Fprintf(os.Stderr, "\n%d %s\n", len(recs), kind)
	return nil
}

// identity <domain> add <name> [-header k:v] [-cookie k=v] [-priv n]
// identity <domain> list
func cmdIdentity(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: tyrion identity <domain> add|list ...")
	}
	domain := strings.ToLower(args[0])
	st, err := store.Open(filepath.Join(".", domain, ".tyrion"))
	if err != nil {
		return err
	}
	switch args[1] {
	case "list":
		for _, r := range st.All(model.KindIdentity) {
			fmt.Printf("%-14s priv=%v headers=%v\n", r["name"], r["privilege"], r["headers"])
		}
		return nil
	case "add":
		if len(args) < 3 {
			return fmt.Errorf("identity add needs a <name>")
		}
		id := &model.Identity{Name: args[2], Headers: map[string]string{}, Cookies: map[string]string{}}
		id.ID = model.ID("identity", domain, id.Name)
		for i := 3; i < len(args); i++ {
			val := func() string {
				i++
				if i < len(args) {
					return args[i]
				}
				return ""
			}
			switch args[i] {
			case "-header":
				k, v, _ := strings.Cut(val(), ":")
				id.Headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
			case "-cookie":
				k, v, _ := strings.Cut(val(), "=")
				id.Cookies[strings.TrimSpace(k)] = strings.TrimSpace(v)
			case "-priv":
				fmt.Sscanf(val(), "%d", &id.Privilege)
			}
		}
		st.Put(id)
		if err := st.Flush(); err != nil {
			return err
		}
		fmt.Printf("added identity %q (priv=%d)\n", id.Name, id.Privilege)
		return nil
	}
	return fmt.Errorf("unknown identity subcommand: %s", args[1])
}

// authz <domain> <request-file>
// request-file format: first line "METHOD URL", then "Header: value" lines,
// a blank line, then an optional body.
func cmdAuthz(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: tyrion authz <domain> <request-file>")
	}
	domain := strings.ToLower(args[0])
	req, err := parseRequestFile(args[1])
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(".", domain, ".tyrion"))
	if err != nil {
		return err
	}
	var ids []*model.Identity
	for _, r := range st.All(model.KindIdentity) {
		ids = append(ids, identityFromMap(r))
	}
	if len(ids) == 0 {
		return fmt.Errorf("no identities defined; add them with `tyrion identity %s add ...`", domain)
	}
	client := httpx.New(5, 15*time.Second)
	rep, err := authz.Compare(client, req, ids)
	if err != nil {
		return err
	}
	fmt.Printf("%s %s\n", rep.Method, rep.URL)
	for _, r := range rep.Results {
		fmt.Printf("  %-14s -> %d  (len %d)\n", r.Identity, r.Status, r.Length)
	}
	fmt.Printf("\nVerdict: %s", rep.Verdict)
	if rep.Verdict != "ok" {
		fmt.Printf("  (confidence %d%%: %s)", rep.Confidence, rep.Reason)
	}
	fmt.Println()

	// Persist a finding + evidence when the comparator flags something.
	if rep.Verdict != "ok" {
		fm := findings.New(st)
		f := fm.Add(&model.Finding{
			Title: "Missing authorization on " + rep.URL, Class: "bfla", Severity: "high",
			Confidence: rep.Confidence, Score: rep.Confidence, Target: rep.URL, Status: "candidate",
			Summary: fmt.Sprintf("%s %s reachable by a lower-privilege identity. %s", rep.Method, rep.URL, rep.Reason),
		})
		for _, r := range rep.Results {
			fm.AddEvidence(&model.Evidence{FindingID: f.ID, Identity: r.Identity, Status: r.Status,
				Request: rep.Method + " " + rep.URL, Response: r.Snippet})
		}
		st.Flush()
		fmt.Printf("recorded finding %s\n", f.ID)
	}
	return nil
}

// report <domain>
func cmdReport(args []string) error {
	domain, err := mustDomain(args)
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(".", domain, ".tyrion"))
	if err != nil {
		return err
	}
	md := reporting.Markdown(st, domain)
	out := filepath.Join(".", domain, "REPORT.md")
	if err := os.WriteFile(out, []byte(md), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", out)
	return nil
}

// monitor <domain> — incremental re-scan reporting the delta.
func cmdMonitor(args []string) error {
	o, _ := parseScanFlags(args)
	o.profile = "continuous"
	domain, err := mustDomain(o.rest)
	if err != nil {
		return err
	}
	workdir, st, err := openProject(o.outdir, domain)
	if err != nil {
		return err
	}
	before := hostSet(st)

	plugins, _ := tools.Load(findPluginsDir())
	prof, _ := config.Get("continuous")
	pc := &pipeline.Context{Target: domain, Workdir: workdir, Store: st, Scope: scope.New(domain),
		Plugins: plugins, Log: func(f string, a ...any) {}}
	eng := engine.New(o.concurrency, o.timeout)
	if _, err := eng.Run(context.Background(), pipeline.Build(pc, prof)); err != nil {
		return err
	}
	st.Flush()

	after := hostSet(st)
	var added, removed []string
	for h := range after {
		if !before[h] {
			added = append(added, h)
		}
	}
	for h := range before {
		if !after[h] {
			removed = append(removed, h)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	fmt.Printf("monitor %s\n", domain)
	fmt.Printf("  + %d new hosts\n", len(added))
	for _, h := range added {
		fmt.Printf("    + %s\n", h)
	}
	fmt.Printf("  - %d gone hosts\n", len(removed))
	for _, h := range removed {
		fmt.Printf("    - %s\n", h)
	}
	return nil
}

// ---- small helpers ------------------------------------------------------

func parseRequestFile(path string) (authz.Request, error) {
	fh, err := os.Open(path)
	if err != nil {
		return authz.Request{}, err
	}
	defer fh.Close()
	req := authz.Request{Headers: map[string]string{}}
	sc := bufio.NewScanner(fh)
	first, inBody := true, false
	var body strings.Builder
	for sc.Scan() {
		line := sc.Text()
		if first {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				return req, fmt.Errorf("first line must be 'METHOD URL'")
			}
			req.Method, req.URL = strings.ToUpper(parts[0]), parts[1]
			first = false
			continue
		}
		if !inBody && strings.TrimSpace(line) == "" {
			inBody = true
			continue
		}
		if inBody {
			body.WriteString(line + "\n")
		} else if k, v, ok := strings.Cut(line, ":"); ok {
			req.Headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	req.Body = strings.TrimSpace(body.String())
	return req, sc.Err()
}

func identityFromMap(r map[string]any) *model.Identity {
	id := &model.Identity{Name: strv(r, "name"), Privilege: numField(r, "privilege"),
		Headers: map[string]string{}, Cookies: map[string]string{}}
	if h, ok := r["headers"].(map[string]any); ok {
		for k, v := range h {
			id.Headers[k] = fmt.Sprint(v)
		}
	}
	if c, ok := r["cookies"].(map[string]any); ok {
		for k, v := range c {
			id.Cookies[k] = fmt.Sprint(v)
		}
	}
	return id
}

func hostSet(st *store.Store) map[string]bool {
	out := map[string]bool{}
	for _, r := range st.All(model.KindAsset) {
		if h := strv(r, "host"); h != "" {
			out[h] = true
		}
	}
	return out
}

func strv(r map[string]any, k string) string { s, _ := r[k].(string); return s }
func numField(r map[string]any, k string) int {
	switch v := r[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}
func boolMark(r map[string]any, k string) string {
	if b, _ := r[k].(bool); b {
		return "IDOR?"
	}
	return ""
}
