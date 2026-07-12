// Command tyrion is the Tyrion V2 platform CLI: a project/scan model backed by
// a DAG engine, a plugin runner, a queryable store, an intelligence layer, and
// an authorization-testing workspace — all in one dependency-free binary.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/0xyoussef404/tyrion/internal/config"
	"github.com/0xyoussef404/tyrion/internal/engine"
	"github.com/0xyoussef404/tyrion/internal/model"
	"github.com/0xyoussef404/tyrion/internal/pipeline"
	"github.com/0xyoussef404/tyrion/internal/scope"
	"github.com/0xyoussef404/tyrion/internal/server"
	"github.com/0xyoussef404/tyrion/internal/store"
	"github.com/0xyoussef404/tyrion/internal/tools"
)

const version = "2.0.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "scan":
		err = cmdScan(args)
	case "doctor":
		err = cmdDoctor(args)
	case "plugin":
		err = cmdPlugin(args)
	case "query":
		err = cmdQuery(args)
	case "export":
		err = cmdExport(args)
	case "assets":
		err = cmdList(args, model.KindAsset)
	case "endpoints":
		err = cmdList(args, model.KindEndpoint)
	case "findings":
		err = cmdList(args, model.KindFinding)
	case "identity":
		err = cmdIdentity(args)
	case "authz":
		err = cmdAuthz(args)
	case "monitor":
		err = cmdMonitor(args)
	case "report":
		err = cmdReport(args)
	case "serve":
		err = cmdServe(args)
	case "version", "-v", "--version":
		fmt.Println("tyrion", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`Tyrion V2 — Recon & Offensive Intelligence Platform

USAGE
  tyrion <command> [args]

COMMANDS
  scan <domain>        Run the recon pipeline (see flags below)
  monitor <domain>     Incremental re-scan; report what changed
  doctor               Check tool health for a profile
  plugin list          List loaded tool plugins
  query <domain> <kind> <expr>   Query the store (e.g. "score>50 and template contains api")
  export <domain> <kind>         Export records (--format txt|json)
  assets|endpoints|findings <domain>   Quick listing
  identity <domain> add <name> [flags]   Register an auth identity
  identity <domain> list
  authz <domain> <request-file>          Multi-identity authorization test
  report <domain>      Regenerate REPORT.md from the store
  serve                Launch the web dashboard
  version

SCAN FLAGS
  -profile <name>    passive|fast|deep|api|infra|continuous (default passive)
  -o <dir>           Output base directory (default .)
  -concurrency <n>   Parallel tasks (default 20)
  -timeout <dur>     Default per-task timeout (default 20m)
  -scope <file>      Scope file (include lines, "!" prefix excludes)

Profiles:
`)
	for _, n := range config.Names() {
		p, _ := config.Get(n)
		fmt.Printf("  %-11s %s\n", n, p.Description)
	}
}

// ---- shared helpers -----------------------------------------------------

type scanOpts struct {
	profile     string
	outdir      string
	concurrency int
	timeout     time.Duration
	scopeFile   string
	rest        []string
}

func parseScanFlags(args []string) (scanOpts, error) {
	o := scanOpts{profile: "passive", outdir: ".", concurrency: 20, timeout: 20 * time.Minute}
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() string {
			i++
			if i < len(args) {
				return args[i]
			}
			return ""
		}
		switch a {
		case "-profile":
			o.profile = next()
		case "-o":
			o.outdir = next()
		case "-concurrency":
			fmt.Sscanf(next(), "%d", &o.concurrency)
		case "-timeout":
			if d, err := time.ParseDuration(next()); err == nil {
				o.timeout = d
			}
		case "-scope":
			o.scopeFile = next()
		default:
			o.rest = append(o.rest, a)
		}
	}
	return o, nil
}

func findPluginsDir() string {
	if d := os.Getenv("TYRION_PLUGINS"); d != "" {
		return d
	}
	candidates := []string{}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "plugins"))
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "..", "plugins"))
	}
	candidates = append(candidates, "plugins", filepath.Join("v2", "plugins"))
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return "plugins"
}

// openProject opens (or creates) a project's workdir + store.
func openProject(outdir, domain string) (workdir string, st *store.Store, err error) {
	workdir = filepath.Join(outdir, domain)
	if err = os.MkdirAll(workdir, 0o755); err != nil {
		return
	}
	st, err = store.Open(filepath.Join(workdir, ".tyrion"))
	return
}

func mustDomain(rest []string) (string, error) {
	if len(rest) == 0 {
		return "", fmt.Errorf("a <domain> argument is required")
	}
	return strings.ToLower(rest[0]), nil
}

// ---- scan ---------------------------------------------------------------

func cmdScan(args []string) error {
	o, err := parseScanFlags(args)
	if err != nil {
		return err
	}
	domain, err := mustDomain(o.rest)
	if err != nil {
		return err
	}
	prof, ok := config.Get(o.profile)
	if !ok {
		return fmt.Errorf("unknown profile %q (%s)", o.profile, strings.Join(config.Names(), "|"))
	}
	plugins, err := tools.Load(findPluginsDir())
	if err != nil {
		return fmt.Errorf("loading plugins: %w", err)
	}
	workdir, st, err := openProject(o.outdir, domain)
	if err != nil {
		return err
	}

	sc := scope.New(domain)
	if o.scopeFile != "" {
		if loaded, err := scope.LoadFile(o.scopeFile); err == nil {
			sc = loaded
		} else {
			return fmt.Errorf("scope file: %w", err)
		}
	}

	pc := &pipeline.Context{
		Target: domain, Workdir: workdir, Store: st, Scope: sc, Plugins: plugins,
		Log: func(f string, a ...any) { fmt.Printf(f+"\n", a...) },
	}

	fmt.Printf("── Tyrion V2 scan ────────────────────────────────\n")
	fmt.Printf("  target=%s profile=%s concurrency=%d timeout=%s\n", domain, o.profile, o.concurrency, o.timeout)

	tasks := pipeline.Build(pc, prof)
	eng := engine.New(o.concurrency, o.timeout)
	eng.Cache = engine.OpenCache(filepath.Join(workdir, ".tyrion", "cache.keys"))
	eng.OnStart = func(id string) { fmt.Printf("▶ %s\n", id) }
	run := &model.ScanRun{ID: model.ID(domain, time.Now().String()), Profile: o.profile, StartedAt: time.Now()}
	eng.OnFinish = func(r engine.TaskResult) {
		icon := map[engine.Status]string{engine.StatusOK: "[ok]", engine.StatusFailed: "[FAIL]", engine.StatusSkipped: "[skip]", engine.StatusCached: "[cache]", engine.StatusTimeout: "[TIMEOUT]"}[r.Status]
		fmt.Printf("%s %s (%s, %s)\n", icon, r.ID, r.Status, r.Duration.Round(time.Millisecond))
		run.Tasks++
		switch r.Status {
		case engine.StatusOK:
			run.OK++
		case engine.StatusFailed, engine.StatusTimeout:
			run.Failed++
		case engine.StatusCached:
			run.Cached++
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	results, err := eng.Run(ctx, tasks)
	if err != nil {
		return err
	}
	run.EndedAt = time.Now()
	run.Duration = run.EndedAt.Sub(run.StartedAt)
	st.Put(run)
	if err := st.Flush(); err != nil {
		return err
	}

	fmt.Printf("── done in %s ── ok=%d failed=%d cached=%d ──\n", run.Duration.Round(time.Second), run.OK, run.Failed, run.Cached)
	fmt.Printf("  assets=%d http=%d urls=%d endpoints=%d\n",
		st.Count(model.KindAsset), st.Count(model.KindHTTPService), st.Count(model.KindURL), st.Count(model.KindEndpoint))
	fmt.Printf("  store: %s  ·  report: %s\n", filepath.Join(workdir, ".tyrion"), filepath.Join(workdir, "REPORT.md"))
	_ = results
	return nil
}

// ---- doctor -------------------------------------------------------------

func cmdDoctor(args []string) error {
	profile := "deep"
	for i := 0; i < len(args); i++ {
		if args[i] == "-profile" && i+1 < len(args) {
			profile = args[i+1]
		}
	}
	plugins, err := tools.Load(findPluginsDir())
	if err != nil {
		return err
	}
	fmt.Printf("Tool health (profile hint: %s)\n\n", profile)
	names := make([]string, 0, len(plugins))
	for n := range plugins {
		names = append(names, n)
	}
	sort.Strings(names)
	ok, miss := 0, 0
	for _, n := range names {
		p := plugins[n]
		if p.Installed() {
			fmt.Printf("  [✔] %-18s %-22s %s\n", n, p.Category, p.Binary)
			ok++
		} else {
			fmt.Printf("  [ ] %-18s %-22s (install %s)\n", n, p.Category, p.Binary)
			miss++
		}
	}
	fmt.Printf("\n%d installed, %d missing, %d plugins total\n", ok, miss, len(plugins))
	return nil
}

// ---- plugin -------------------------------------------------------------

func cmdPlugin(args []string) error {
	plugins, err := tools.Load(findPluginsDir())
	if err != nil {
		return err
	}
	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "list":
		byCat := map[string][]string{}
		for n, p := range plugins {
			byCat[p.Category] = append(byCat[p.Category], n)
		}
		cats := make([]string, 0, len(byCat))
		for c := range byCat {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		for _, c := range cats {
			sort.Strings(byCat[c])
			fmt.Printf("%s:\n", c)
			for _, n := range byCat[c] {
				mark := " "
				if plugins[n].Installed() {
					mark = "✔"
				}
				fmt.Printf("  [%s] %s\n", mark, n)
			}
		}
		fmt.Printf("\n%d plugins from %s\n", len(plugins), findPluginsDir())
	default:
		return fmt.Errorf("unknown plugin subcommand: %s", sub)
	}
	return nil
}

// ---- serve --------------------------------------------------------------

func cmdServe(args []string) error {
	addr, base := "127.0.0.1:8088", "."
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-addr":
			if i+1 < len(args) {
				i++
				addr = args[i]
			}
		case "-base":
			if i+1 < len(args) {
				i++
				base = args[i]
			}
		}
	}
	return server.New(base).Listen(addr)
}
