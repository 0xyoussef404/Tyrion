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

	"github.com/0xyoussef404/tyrion/internal/active"
	"github.com/0xyoussef404/tyrion/internal/authz"
	"github.com/0xyoussef404/tyrion/internal/config"
	"github.com/0xyoussef404/tyrion/internal/engine"
	"github.com/0xyoussef404/tyrion/internal/findings"
	"github.com/0xyoussef404/tyrion/internal/httpx"
	"github.com/0xyoussef404/tyrion/internal/intel"
	"github.com/0xyoussef404/tyrion/internal/model"
	"github.com/0xyoussef404/tyrion/internal/notify"
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
		return fmt.Errorf("usage: tyrion authz <domain> <request-file> [-read <read-request-file>]")
	}
	domain := strings.ToLower(args[0])
	req, err := parseRequestFile(args[1])
	if err != nil {
		return err
	}
	// Optional read request enables the state-change detector.
	var readReq *authz.Request
	for i := 2; i < len(args); i++ {
		if args[i] == "-read" && i+1 < len(args) {
			r, err := parseRequestFile(args[i+1])
			if err != nil {
				return err
			}
			readReq = &r
		}
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
		severity, status := "high", "candidate"
		summary := fmt.Sprintf("%s %s reachable by a lower-privilege identity. %s", rep.Method, rep.URL, rep.Reason)

		// State-change verification promotes candidate -> confirmed.
		if readReq != nil {
			if off := offendingIdentity(rep, ids); off != nil {
				sr := authz.VerifyStateChange(client, rep.Request, *readReq, off)
				fmt.Printf("\nState-change check as %q: %s\n", off.Name, sr.Note)
				if sr.Changed {
					severity, status = "critical", "confirmed"
					summary += " State change CONFIRMED via before/after read diff."
				}
			}
		}

		fm := findings.New(st)
		f := fm.Add(&model.Finding{
			Title: "Missing authorization on " + rep.URL, Class: "bfla", Severity: severity,
			Confidence: rep.Confidence, Score: rep.Confidence, Target: rep.URL, Status: status,
			Summary: summary,
		})
		for _, r := range rep.Results {
			fm.AddEvidence(&model.Evidence{FindingID: f.ID, Identity: r.Identity, Status: r.Status,
				Request: rep.Method + " " + rep.URL, Response: r.Snippet})
		}
		st.Flush()
		fmt.Printf("recorded finding %s [%s/%s]\n", f.ID, severity, status)
	}
	return nil
}

// offendingIdentity returns the lower-privilege identity that got a successful
// response (the one that shouldn't have access).
func offendingIdentity(rep *authz.Report, ids []*model.Identity) *model.Identity {
	byName := map[string]*model.Identity{}
	for _, id := range ids {
		byName[id.Name] = id
	}
	maxPriv := 0
	for _, r := range rep.Results {
		if r.Status >= 200 && r.Status < 300 && r.Privilege > maxPriv {
			maxPriv = r.Privilege
		}
	}
	var best *model.Identity
	for _, r := range rep.Results {
		if r.Status >= 200 && r.Status < 300 && r.Privilege < maxPriv {
			if best == nil || r.Privilege < best.Privilege {
				best = byName[r.Identity]
			}
		}
	}
	return best
}

// graph <domain> — correlation clusters (shared favicon / TLS cert).
func cmdGraph(args []string) error {
	domain, err := mustDomain(args)
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(".", domain, ".tyrion"))
	if err != nil {
		return err
	}
	var svcs []*model.HTTPService
	for _, r := range st.All(model.KindHTTPService) {
		svcs = append(svcs, &model.HTTPService{Host: strv(r, "host"),
			FaviconHash: strv(r, "favicon_hash"), TLSCertHash: strv(r, "tls_cert_hash")})
	}
	clusters, edges := intel.Correlate(svcs)
	fmt.Printf("Asset graph: %d edges, %d correlation clusters\n\n", len(edges), len(clusters))
	for _, c := range clusters {
		fmt.Printf("• %s (%d hosts share this signal):\n", c.Signal, len(c.Hosts))
		for _, h := range c.Hosts {
			fmt.Printf("    %s\n", h)
		}
	}
	// Also summarize stored edges by relation.
	byRel := map[string]int{}
	for _, e := range st.All(model.KindEdge) {
		byRel[strv(e, "rel")]++
	}
	if len(byRel) > 0 {
		fmt.Println("\nStored edges by relation:")
		for rel, n := range byRel {
			fmt.Printf("    %-26s %d\n", rel, n)
		}
	}
	return nil
}

// authz-batch <domain> -base <url> [-limit n] — the BOLA/BFLA workspace: turn
// every IDOR-candidate / sensitive endpoint into a concrete request and replay
// it across all identities.
func cmdAuthzBatch(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: tyrion authz-batch <domain> -base <url> [-limit n]")
	}
	domain := strings.ToLower(args[0])
	base, limit := "", 40
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-base":
			if i+1 < len(args) {
				i++
				base = strings.TrimRight(args[i], "/")
			}
		case "-limit":
			if i+1 < len(args) {
				i++
				fmt.Sscanf(args[i], "%d", &limit)
			}
		}
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

	// Candidate endpoints: IDOR candidates first, then other sensitive ones.
	targets := st.All(model.KindEndpoint)
	sort.Slice(targets, func(i, j int) bool { return numField(targets[i], "score") > numField(targets[j], "score") })

	client := httpx.New(5, 15*time.Second)
	fm := findings.New(st)
	tested, flagged := 0, 0
	for _, e := range targets {
		if tested >= limit {
			break
		}
		if !boolField(e, "idor_candidate") && !boolField(e, "sensitive") {
			continue
		}
		url := concreteURL(strv(e, "template"), base)
		if url == "" {
			continue
		}
		tested++
		rep, err := authz.Compare(client, authz.Request{Method: "GET", URL: url}, ids)
		if err != nil {
			continue
		}
		if rep.Verdict == "ok" {
			continue
		}
		flagged++
		f := fm.Add(&model.Finding{
			Title: "Broken object/function level authorization on " + url, Class: "bola",
			Severity: "high", Confidence: rep.Confidence, Score: rep.Confidence, Target: url,
			Status: "candidate", Summary: fmt.Sprintf("GET %s reachable by lower-privilege identity. %s", url, rep.Reason),
		})
		for _, r := range rep.Results {
			fm.AddEvidence(&model.Evidence{FindingID: f.ID, Identity: r.Identity, Status: r.Status,
				Request: "GET " + url, Response: r.Snippet})
		}
		fmt.Printf("[flag] %-6s %s (conf %d%%)\n", "GET", url, rep.Confidence)
	}
	st.Flush()
	fmt.Printf("\nbatch authz: tested %d endpoints, flagged %d (findings recorded)\n", tested, flagged)
	return nil
}

// concreteURL turns a normalized template into a fetchable URL by filling in
// placeholder variable types with safe probe values.
func concreteURL(template, base string) string {
	repl := strings.NewReplacer(
		"{integer}", "1",
		"{uuid}", "00000000-0000-0000-0000-000000000001",
		"{mongoid}", "000000000000000000000001",
		"{hash}", "0000000000000000000000000000000000000000",
		"{slug}", "test",
		"{date}", "2024-01-01",
		"{email}", "test@example.com",
		"{base64}", "dGVzdA==",
		"{jwt}", "x",
	)
	u := repl.Replace(template)
	if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		return u
	}
	// When a base is given, it owns scheme+host; take only the path from the
	// template (templates are stored as host/path).
	if base != "" {
		path := u
		if !strings.HasPrefix(u, "/") {
			if idx := strings.Index(u, "/"); idx >= 0 {
				path = u[idx:]
			} else {
				path = "/"
			}
		}
		return base + path
	}
	if strings.Contains(u, "/") && !strings.HasPrefix(u, "/") {
		return "https://" + u
	}
	return ""
}

// dorks <domain>
func cmdDorks(args []string) error {
	domain, err := mustDomain(args)
	if err != nil {
		return err
	}
	d := intel.Dorks(domain)
	for _, src := range []string{"google", "github", "shodan"} {
		fmt.Printf("# %s\n", src)
		for _, q := range d[src] {
			fmt.Println(q)
		}
		fmt.Println()
	}
	return nil
}

// bypass <url> — active 401/403 bypass attempts.
func cmdBypass(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: tyrion bypass <url>")
	}
	url := args[0]
	client := httpx.New(5, 15*time.Second)
	base, err := client.Do("GET", url, nil, nil, "baseline")
	if err != nil {
		return err
	}
	fmt.Printf("baseline %s -> %d\n", url, base.Status)
	hits := active.RunBypass(client, url, base.Status)
	if len(hits) == 0 {
		fmt.Println("no bypass found")
		return nil
	}
	for _, h := range hits {
		fmt.Printf("[BYPASS %d] %-20s %s %v\n", h.Status, h.Label, h.URL, h.Headers)
	}
	return nil
}

// cors <url> — active CORS misconfiguration check.
func cmdCORS(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: tyrion cors <url>")
	}
	res := active.CheckCORS(httpx.New(5, 15*time.Second), args[0])
	if res.Vulnerable {
		fmt.Printf("[VULNERABLE] %s\n  %s\n  ACAO=%s ACAC=%s\n", res.URL, res.Reason, res.ACAO, res.ACAC)
	} else {
		fmt.Printf("[ok] %s (ACAO=%q)\n", res.URL, res.ACAO)
	}
	return nil
}

// params <domain> — mined parameters (from store, else from urls).
func cmdParams(args []string) error {
	domain, err := mustDomain(args)
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(".", domain, ".tyrion"))
	if err != nil {
		return err
	}
	if st.Count(model.KindParameter) > 0 {
		for _, r := range st.All(model.KindParameter) {
			fmt.Println(strv(r, "name"))
		}
		return nil
	}
	var urls []string
	for _, r := range st.All(model.KindURL) {
		urls = append(urls, strv(r, "raw"))
	}
	for _, p := range intel.MineParams(urls) {
		fmt.Printf("%-24s %d\n", p.Name, p.Count)
	}
	return nil
}

// juicy <domain> — juicy URLs grouped by category.
func cmdJuicy(args []string) error {
	domain, err := mustDomain(args)
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(".", domain, ".tyrion"))
	if err != nil {
		return err
	}
	var urls []string
	for _, r := range st.All(model.KindURL) {
		urls = append(urls, strv(r, "raw"))
	}
	buckets := intel.JuicyBuckets(urls)
	cats := make([]string, 0, len(buckets))
	for c := range buckets {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		fmt.Printf("# %s (%d)\n", c, len(buckets[c]))
		for _, u := range buckets[c] {
			fmt.Println(u)
		}
		fmt.Println()
	}
	return nil
}

// playbook <domain> — tech attack suggestions from detected technologies.
func cmdPlaybook(args []string) error {
	domain, err := mustDomain(args)
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(".", domain, ".tyrion"))
	if err != nil {
		return err
	}
	techSet := map[string]bool{}
	for _, s := range st.All(model.KindHTTPService) {
		if arr, ok := s["tech"].([]any); ok {
			for _, t := range arr {
				techSet[fmt.Sprint(t)] = true
			}
		}
	}
	var techs []string
	for t := range techSet {
		techs = append(techs, t)
	}
	plays := intel.PlaybookFor(techs)
	if len(plays) == 0 {
		fmt.Println("no known-tech playbooks matched (detected tech:", techs, ")")
		return nil
	}
	for tech, ps := range plays {
		fmt.Printf("# %s\n", tech)
		for _, p := range ps {
			fmt.Printf("  - %s\n", p)
		}
	}
	return nil
}

// watch <domain> -interval <dur> — continuous monitoring loop.
func cmdWatch(args []string) error {
	interval := time.Hour
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "-interval" && i+1 < len(args) {
			if d, err := time.ParseDuration(args[i+1]); err == nil {
				interval = d
			}
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	domain, err := mustDomain(rest)
	if err != nil {
		return err
	}
	settings := config.Load()
	notifier := notify.New(settings.Webhook)
	fmt.Printf("watching %s every %s (Ctrl-C to stop)\n", domain, interval)
	for {
		added, removed, e := runContinuous(domain)
		if e != nil {
			fmt.Fprintln(os.Stderr, "watch error:", e)
		} else {
			fmt.Printf("[%s] +%d new, -%d gone hosts\n", time.Now().Format("15:04:05"), len(added), len(removed))
			if len(added) > 0 && notifier.Enabled() {
				notifier.Send("Tyrion watch: "+domain,
					fmt.Sprintf("%d new hosts:\n%s", len(added), strings.Join(added, "\n")))
			}
		}
		time.Sleep(interval)
	}
}

// runContinuous runs one continuous-profile pass and returns the host delta.
func runContinuous(domain string) (added, removed []string, err error) {
	workdir, st, err := openProject(".", domain)
	if err != nil {
		return nil, nil, err
	}
	before := hostSet(st)
	plugins, _ := tools.Load(findPluginsDir())
	prof, _ := config.Get("continuous")
	pc := &pipeline.Context{Target: domain, Workdir: workdir, Store: st, Scope: scope.New(domain),
		Plugins: plugins, Client: httpx.New(10, 15*time.Second), Log: func(string, ...any) {}}
	eng := engine.New(20, 20*time.Minute)
	if _, err := eng.Run(context.Background(), pipeline.Build(pc, prof)); err != nil {
		return nil, nil, err
	}
	st.Flush()
	after := hostSet(st)
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
	return added, removed, nil
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
func boolField(r map[string]any, k string) bool { b, _ := r[k].(bool); return b }
func boolMark(r map[string]any, k string) string {
	if b, _ := r[k].(bool); b {
		return "IDOR?"
	}
	return ""
}
