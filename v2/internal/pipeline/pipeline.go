// Package pipeline wires recon stages into a DAG. Each stage reads/writes the
// store and drives external tools through the plugin runner. Stages with no
// dependency on each other run concurrently.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0xyoussef404/tyrion/internal/config"
	"github.com/0xyoussef404/tyrion/internal/engine"
	"github.com/0xyoussef404/tyrion/internal/httpx"
	"github.com/0xyoussef404/tyrion/internal/intel"
	"github.com/0xyoussef404/tyrion/internal/model"
	"github.com/0xyoussef404/tyrion/internal/reporting"
	"github.com/0xyoussef404/tyrion/internal/scope"
	"github.com/0xyoussef404/tyrion/internal/store"
	"github.com/0xyoussef404/tyrion/internal/tools"
)

// Context is shared state passed to every stage.
type Context struct {
	Target  string
	Workdir string
	Store   *store.Store
	Scope   *scope.Scope
	Plugins map[string]*tools.Plugin
	Client  *httpx.Client // shared HTTP service (fetching JS, specs, ...)
	Log     func(format string, args ...any)
}

// stageFn implements one stage.
type stageFn func(ctx context.Context, pc *Context) error

// desiredDeps maps a stage to the stages it prefers to run after. The builder
// intersects these with the stages actually present in the profile.
var desiredDeps = map[string][]string{
	config.StageDNSResolve:  {config.StageSubEnum},
	config.StageASN:         {config.StageSubEnum},
	config.StageArchives:    {config.StageSubEnum},
	config.StageHTTPProbe:   {config.StageDNSResolve},
	config.StagePortScan:    {config.StageDNSResolve},
	config.StageTakeover:    {config.StageDNSResolve},
	config.StageCrawl:       {config.StageHTTPProbe},
	config.StageNuclei:      {config.StageHTTPProbe},
	config.StageScreens:     {config.StageHTTPProbe},
	config.StageGraph:       {config.StageHTTPProbe},
	config.StageJS:          {config.StageHTTPProbe, config.StageCrawl, config.StageArchives},
	config.StageSwagger:     {config.StageCrawl, config.StageArchives, config.StageJS},
	config.StageGraphQL:     {config.StageCrawl, config.StageJS},
	config.StageAuthSurface: {config.StageCrawl, config.StageArchives, config.StageHTTPProbe},
	config.StageNormalize:   {config.StageCrawl, config.StageArchives, config.StageHTTPProbe},
	config.StageScore:       {config.StageNormalize},
}

var stageImpl = map[string]stageFn{
	config.StageSubEnum:     stageSubEnum,
	config.StageDNSResolve:  stageDNSResolve,
	config.StageHTTPProbe:   stageHTTPProbe,
	config.StageASN:         stageGenericTool("asn-map", "asnmap", "asn.txt"),
	config.StagePortScan:    stageGenericTool("port-scan", "naabu", "open_ports.txt"),
	config.StageCrawl:       stageCrawl,
	config.StageArchives:    stageArchives,
	config.StageJS:          stageJS,
	config.StageNuclei:      stageGenericTool("nuclei", "nuclei", "nuclei.jsonl"),
	config.StageTakeover:    stageGenericTool("takeover", "nuclei-takeover", "takeover.txt"),
	config.StageScreens:     stageGenericTool("screenshots", "gowitness", "gowitness.log"),
	config.StageSwagger:     stageSwagger,
	config.StageGraphQL:     stageGraphQL,
	config.StageAuthSurface: stageAuthSurface,
	config.StageNormalize:   stageNormalize,
	config.StageScore:       stageScore,
	config.StageGraph:       stageCorrelate,
	config.StageReport:      stageReport,
}

// Build converts a profile into a DAG of engine tasks.
func Build(pc *Context, prof config.Profile) []engine.Task {
	present := map[string]bool{}
	for _, s := range prof.Stages {
		present[s] = true
	}
	var tasks []engine.Task
	for _, s := range prof.Stages {
		fn := stageImpl[s]
		if fn == nil {
			continue
		}
		var deps []string
		if s == config.StageReport {
			// Report runs last: depend on every other included stage.
			for _, other := range prof.Stages {
				if other != config.StageReport {
					deps = append(deps, other)
				}
			}
		} else {
			for _, d := range desiredDeps[s] {
				if present[d] {
					deps = append(deps, d)
				}
			}
		}
		deps = model.SortedUnique(deps)
		stage := s
		f := fn
		tasks = append(tasks, engine.Task{
			ID:        stage,
			DependsOn: deps,
			Run: func(ctx context.Context) error {
				return f(ctx, pc)
			},
		})
	}
	return tasks
}

// ---- helpers ------------------------------------------------------------

func (pc *Context) run(ctx context.Context, name string, vars map[string]string) (*tools.Result, error) {
	p := pc.Plugins[name]
	if p == nil {
		return nil, fmt.Errorf("plugin %q not found", name)
	}
	if !p.Installed() {
		pc.Log("  [skip] %s not installed", p.Binary)
		return &tools.Result{}, nil
	}
	if vars == nil {
		vars = map[string]string{}
	}
	vars["target"] = pc.Target
	res, err := p.Run(ctx, pc.Workdir, vars)
	if res != nil {
		pc.Store.Put(&model.ToolRun{
			ID: model.ID(name, time.Now().String()), Tool: name, ExitCode: res.ExitCode,
			Duration: res.Duration, TimedOut: res.TimedOut, Lines: len(res.Lines), At: time.Now(),
		})
	}
	return res, err
}

func (pc *Context) writeLines(name string, lines []string) {
	_ = os.WriteFile(filepath.Join(pc.Workdir, name), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func (pc *Context) urlsInStore() []string {
	var out []string
	for _, r := range pc.Store.All(model.KindURL) {
		if raw, _ := r["raw"].(string); raw != "" {
			out = append(out, raw)
		}
	}
	return out
}

// ---- stages -------------------------------------------------------------

func stageSubEnum(ctx context.Context, pc *Context) error {
	var hosts []string
	for _, name := range []string{"subfinder", "assetfinder"} {
		res, err := pc.run(ctx, name, nil)
		if err != nil {
			pc.Log("  [warn] %s: %v", name, err)
			continue
		}
		for _, h := range res.Lines {
			hosts = append(hosts, strings.ToLower(strings.TrimSpace(h)))
		}
	}
	hosts = pc.Scope.Filter(model.SortedUnique(hosts))
	if len(hosts) == 0 {
		hosts = []string{pc.Target} // always keep the root in play
	}
	now := time.Now()
	for _, h := range hosts {
		pc.Store.Put(&model.Asset{ID: model.ID(h), Host: h, Source: "passive", FirstSeen: now, LastSeen: now})
	}
	pc.writeLines("all_subs.txt", hosts)
	pc.writeLines("roots.txt", []string{pc.Target})
	pc.Log("  subdomains: %d", len(hosts))
	return nil
}

func stageDNSResolve(ctx context.Context, pc *Context) error {
	res, err := pc.run(ctx, "dnsx", map[string]string{"infile": "all_subs.txt"})
	if err != nil {
		return err
	}
	alive := map[string]bool{}
	for _, line := range res.Lines {
		host := strings.Fields(line)[0]
		alive[strings.ToLower(host)] = true
	}
	n := 0
	for _, r := range pc.Store.All(model.KindAsset) {
		h, _ := r["host"].(string)
		if alive[strings.ToLower(h)] {
			a := &model.Asset{ID: model.ID(h), Host: h, Alive: true, LastSeen: time.Now(), Source: "dns"}
			pc.Store.Put(a)
			n++
		}
	}
	pc.Log("  resolved: %d", n)
	return nil
}

func stageHTTPProbe(ctx context.Context, pc *Context) error {
	// Feed resolved hosts if we have them; otherwise all subs.
	infile := "all_subs.txt"
	if _, err := os.Stat(filepath.Join(pc.Workdir, "resolved.txt")); err == nil {
		infile = "resolved.txt"
	}
	res, err := pc.run(ctx, "httpx", map[string]string{"infile": infile})
	if err != nil {
		return err
	}
	var live []string
	for _, line := range strings.Split(res.Raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var j map[string]any
		if json.Unmarshal([]byte(line), &j) != nil {
			continue
		}
		url, _ := j["url"].(string)
		if url == "" {
			continue
		}
		host := hostOf(url)
		if !pc.Scope.Allows(host) {
			continue
		}
		svc := &model.HTTPService{
			ID: model.ID(url), Host: host, URL: url,
			Status: intField(j, "status_code"), Title: strField(j, "title"),
			Server: strField(j, "webserver"), ContentType: strField(j, "content_type"),
			Length: intField(j, "content_length"), Tech: strSlice(j, "tech"),
			FaviconHash: strField(j, "favicon"),
		}
		pc.Store.Put(svc)
		live = append(live, url)
	}
	pc.writeLines("live_hosts.txt", model.SortedUnique(live))
	pc.Log("  live http: %d", len(live))
	return nil
}

func stageCrawl(ctx context.Context, pc *Context) error {
	res, err := pc.run(ctx, "katana", map[string]string{"infile": "live_hosts.txt"})
	if err != nil {
		return err
	}
	pc.ingestURLs(res.Lines, "katana")
	pc.Log("  crawled urls: %d", len(res.Lines))
	return nil
}

func stageArchives(ctx context.Context, pc *Context) error {
	var all []string
	for _, name := range []string{"gau", "waybackurls"} {
		res, err := pc.run(ctx, name, map[string]string{"infile": "roots.txt"})
		if err != nil {
			continue
		}
		all = append(all, res.Lines...)
	}
	pc.ingestURLs(all, "archive")
	pc.Log("  archive urls: %d", len(all))
	return nil
}

func stageJS(ctx context.Context, pc *Context) error {
	// Collect JS URLs.
	var jsURLs []string
	for _, u := range pc.urlsInStore() {
		if strings.Contains(strings.ToLower(u), ".js") {
			jsURLs = append(jsURLs, u)
			pc.Store.Put(&model.URL{ID: model.ID("js", u), Raw: u, Host: hostOf(u), Path: pathOf(u), Source: "js"})
		}
	}
	jsURLs = model.SortedUnique(jsURLs)

	// Fetch & analyze (bounded) — needs the shared HTTP client.
	fetched, eps, secrets := 0, 0, 0
	if pc.Client != nil {
		limit := 60
		for i, u := range jsURLs {
			if i >= limit {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			resp, err := pc.Client.Do("GET", u, nil, nil, "recon")
			if err != nil || resp == nil || len(resp.Body) == 0 {
				continue
			}
			fetched++
			a := intel.AnalyzeJS(u, string(resp.Body))
			for _, ep := range a.Endpoints {
				nz := intel.Normalize(ep)
				pc.Store.Put(&model.Endpoint{ID: model.ID("ep", nz.Template), Template: nz.Template,
					VarTypes: nz.VarTypes, IDORCand: nz.IsIDORCandidate(),
					Sensitive: intel.Sensitive(nz.Template), Source: "js", Count: 1})
				eps++
			}
			for _, abs := range a.URLs {
				if pc.Scope.Allows(hostOf(abs)) {
					pc.Store.Put(&model.URL{ID: model.ID(abs), Raw: abs, Host: hostOf(abs), Path: pathOf(abs), Source: "js"})
				}
			}
			for _, s := range a.Secrets {
				pc.Store.Put(s)
				secrets++
			}
		}
	}
	pc.Log("  javascript: %d urls, %d fetched, %d endpoints, %d secrets", len(jsURLs), fetched, eps, secrets)
	return nil
}

func stageSwagger(ctx context.Context, pc *Context) error {
	var curls, unauth []string
	specs, ops := 0, 0
	for _, u := range pc.urlsInStore() {
		l := strings.ToLower(u)
		if !(strings.Contains(l, "swagger") || strings.Contains(l, "openapi") || strings.Contains(l, "api-docs")) {
			continue
		}
		if pc.Client == nil {
			pc.Store.Put(&model.Endpoint{ID: model.ID("swagger", u), Template: intel.Normalize(u).Template,
				Sensitive: true, Source: "swagger", Count: 1})
			continue
		}
		resp, err := pc.Client.Do("GET", u, nil, nil, "recon")
		if err != nil || resp == nil || resp.Status != 200 {
			continue
		}
		eps, base := intel.ParseOpenAPI(resp.Body)
		if len(eps) == 0 {
			continue
		}
		specs++
		if base == "" {
			base = "https://" + hostOf(u)
		}
		for _, ep := range eps {
			ops++
			pc.Store.Put(&model.Endpoint{
				ID: model.ID("swagger", ep.Method, base+ep.Path), Template: intel.Normalize(base + ep.Path).Template,
				Methods: []string{ep.Method}, Params: ep.Params, Sensitive: true, Source: "swagger", Count: 1,
			})
			curls = append(curls, ep.Curl(base))
			if !ep.Auth {
				unauth = append(unauth, ep.Method+" "+base+ep.Path)
			}
		}
	}
	if len(curls) > 0 {
		pc.writeLines("swagger_curls.txt", curls)
	}
	if len(unauth) > 0 {
		pc.writeLines("swagger_unauth.txt", unauth)
	}
	pc.Log("  swagger: %d specs, %d operations, %d unauthenticated", specs, ops, len(unauth))
	return nil
}

func stageGraphQL(ctx context.Context, pc *Context) error {
	var curls []string
	n := 0
	for _, u := range pc.urlsInStore() {
		if !strings.Contains(strings.ToLower(u), "graphql") {
			continue
		}
		pc.Store.Put(&model.Endpoint{ID: model.ID("graphql", u), Template: intel.Normalize(u).Template,
			Sensitive: true, Source: "graphql", Count: 1})
		curls = append(curls, intel.IntrospectionCurl(u))
		n++
	}
	if len(curls) > 0 {
		pc.writeLines("graphql_introspection.txt", model.SortedUnique(curls))
	}
	pc.Log("  graphql endpoints: %d (introspection probes written)", n)
	return nil
}

func stageAuthSurface(ctx context.Context, pc *Context) error {
	n := 0
	for _, r := range pc.Store.All(model.KindURL) {
		raw, _ := r["raw"].(string)
		if raw == "" {
			continue
		}
		if intel.ScoreEndpoint(raw, nil, nil, 0, nil, false).Components["auth_surface"] > 0 {
			u := &model.URL{ID: model.ID(raw), Raw: raw, Host: hostOf(raw), Path: pathOf(raw),
				AuthSurface: true, Source: strField(r, "source")}
			pc.Store.Put(u)
			n++
		}
	}
	pc.Log("  auth-surface urls: %d", n)
	return nil
}

func stageNormalize(ctx context.Context, pc *Context) error {
	agg := map[string]*model.Endpoint{}
	for _, u := range pc.urlsInStore() {
		nz := intel.Normalize(u)
		id := model.ID("ep", nz.Template)
		e := agg[id]
		if e == nil {
			e = &model.Endpoint{ID: id, Template: nz.Template, VarTypes: nz.VarTypes,
				IDORCand: nz.IsIDORCandidate(), Sensitive: intel.Sensitive(nz.Template), Source: "normalize"}
			agg[id] = e
		}
		e.Count++
		e.Params = model.SortedUnique(append(e.Params, nz.Params...))
	}
	for _, e := range agg {
		pc.Store.Put(e)
	}
	pc.Log("  normalized endpoints: %d (from urls)", len(agg))
	return nil
}

func stageScore(ctx context.Context, pc *Context) error {
	// Tech per host, for the tech-risk component.
	techByHost := map[string][]string{}
	for _, s := range pc.Store.All(model.KindHTTPService) {
		host, _ := s["host"].(string)
		techByHost[host] = strSlice(s, "tech")
	}
	for _, r := range pc.Store.All(model.KindEndpoint) {
		id, _ := r["id"].(string)
		tmpl, _ := r["template"].(string)
		sc := intel.ScoreEndpoint(tmpl, strSlice(r, "params"), strSlice(r, "var_types"), 0, techByHost[hostOf(tmpl)], false)
		e := &model.Endpoint{
			ID: id, Template: tmpl, Params: strSlice(r, "params"), VarTypes: strSlice(r, "var_types"),
			Count: intField(r, "count"), Score: sc.Total, Sensitive: boolField(r, "sensitive"),
			IDORCand: boolField(r, "idor_candidate"), Source: strField(r, "source"),
			Methods: strSlice(r, "methods"),
		}
		pc.Store.Put(e)
	}
	pc.Log("  scored %d endpoints", pc.Store.Count(model.KindEndpoint))
	return nil
}

func stageCorrelate(ctx context.Context, pc *Context) error {
	var svcs []*model.HTTPService
	for _, r := range pc.Store.All(model.KindHTTPService) {
		svcs = append(svcs, &model.HTTPService{Host: strField(r, "host"),
			FaviconHash: strField(r, "favicon_hash"), TLSCertHash: strField(r, "tls_cert_hash")})
	}
	clusters, edges := intel.Correlate(svcs)
	for _, e := range edges {
		pc.Store.Put(e)
	}
	pc.Log("  correlation: %d clusters, %d edges", len(clusters), len(edges))
	return nil
}

func stageReport(ctx context.Context, pc *Context) error {
	md := reporting.Markdown(pc.Store, pc.Target)
	_ = os.WriteFile(filepath.Join(pc.Workdir, "REPORT.md"), []byte(md), 0o644)
	pc.Log("  report: REPORT.md")
	return nil
}

// stageGenericTool runs a plugin and stores its raw output to a file. Used for
// heavier active tools whose findings are consumed as-is (nuclei, ports, ...).
func stageGenericTool(stage, plugin, outfile string) stageFn {
	return func(ctx context.Context, pc *Context) error {
		vars := map[string]string{"infile": "live_hosts.txt"}
		res, err := pc.run(ctx, plugin, vars)
		if err != nil {
			pc.Log("  [warn] %s: %v", plugin, err)
			return nil
		}
		if res.Raw != "" {
			_ = os.WriteFile(filepath.Join(pc.Workdir, outfile), []byte(res.Raw), 0o644)
		}
		pc.Log("  %s: %d lines -> %s", stage, len(res.Lines), outfile)
		return nil
	}
}

func (pc *Context) ingestURLs(urls []string, src string) {
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" || !strings.HasPrefix(u, "http") {
			continue
		}
		if !pc.Scope.Allows(hostOf(u)) {
			continue
		}
		pc.Store.Put(&model.URL{ID: model.ID(u), Raw: u, Host: hostOf(u), Path: pathOf(u), Source: src})
	}
}

// ---- small field/url helpers -------------------------------------------

func strField(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func intField(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}
func boolField(m map[string]any, k string) bool { b, _ := m[k].(bool); return b }
func strSlice(m map[string]any, k string) []string {
	switch v := m[k].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			out = append(out, fmt.Sprint(e))
		}
		return out
	}
	return nil
}

func hostOf(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	return s
}

func pathOf(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/"); i >= 0 {
		p := s[i:]
		if j := strings.IndexAny(p, "?#"); j >= 0 {
			p = p[:j]
		}
		return p
	}
	return "/"
}

var _ = sort.Strings
