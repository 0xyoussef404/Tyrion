// Package tools loads external-tool plugin definitions and runs them as
// subprocesses. Adding a new recon tool is a matter of dropping a YAML file in
// plugins/ — no core code changes.
package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/0xyoussef404/tyrion/internal/pluginfmt"
)

// Plugin describes one external tool.
type Plugin struct {
	Name      string
	Category  string
	Binary    string
	Args      []string
	Parser    string // lines | json | host-lines
	Field     string // json field to extract when Parser == json
	StdinFile string // if set, this template file is piped to stdin
	Timeout   time.Duration
	RateLimit int
}

// Load reads all plugin YAML files from a directory.
func Load(dir string) (map[string]*Plugin, error) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.yaml"))
	more, _ := filepath.Glob(filepath.Join(dir, "*.yml"))
	files = append(files, more...)
	out := map[string]*Plugin{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		m, err := pluginfmt.Parse(string(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		p := &Plugin{
			Name:      pluginfmt.String(m, "name", strings.TrimSuffix(filepath.Base(f), filepath.Ext(f))),
			Category:  pluginfmt.String(m, "category", "misc"),
			Binary:    pluginfmt.String(m, "binary", ""),
			Args:      pluginfmt.List(m, "args"),
			Parser:    pluginfmt.String(m, "parser", "lines"),
			Field:     pluginfmt.String(m, "field", ""),
			StdinFile: pluginfmt.String(m, "stdin_file", ""),
		}
		p.Timeout = parseDur(pluginfmt.String(m, "timeout", "10m"), 10*time.Minute)
		p.RateLimit, _ = strconv.Atoi(pluginfmt.String(m, "rate_limit", "0"))
		if p.Binary == "" {
			p.Binary = p.Name
		}
		out[p.Name] = p
	}
	return out, nil
}

// Installed reports whether the plugin's binary is on PATH.
func (p *Plugin) Installed() bool {
	_, err := exec.LookPath(p.Binary)
	return err == nil
}

// Result is the outcome of running a plugin.
type Result struct {
	Lines    []string
	Raw      string
	ExitCode int
	Duration time.Duration
	TimedOut bool
}

// Run executes the plugin. vars substitutes {{key}} placeholders in args and
// the stdin file (e.g. {{target}}, {{outdir}}).
func (p *Plugin) Run(ctx context.Context, workdir string, vars map[string]string) (*Result, error) {
	if !p.Installed() {
		return nil, fmt.Errorf("tool not installed: %s", p.Binary)
	}
	args := make([]string, len(p.Args))
	for i, a := range p.Args {
		args[i] = subst(a, vars)
	}
	cctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, p.Binary, args...)
	cmd.Dir = workdir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if p.StdinFile != "" {
		fpath := filepath.Join(workdir, subst(p.StdinFile, vars))
		fh, err := os.Open(fpath)
		if err != nil {
			return nil, fmt.Errorf("stdin file %s: %w", fpath, err)
		}
		defer fh.Close()
		cmd.Stdin = fh
	}

	start := time.Now()
	err := cmd.Run()
	res := &Result{Duration: time.Since(start), Raw: stdout.String()}
	if cctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
	}
	if ee, ok := err.(*exec.ExitError); ok {
		res.ExitCode = ee.ExitCode()
	} else if err != nil && !res.TimedOut {
		return res, err
	}
	res.Lines = p.parse(stdout.Bytes())
	return res, nil
}

func (p *Plugin) parse(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		switch p.Parser {
		case "json":
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) == nil {
				if v, ok := m[p.Field]; ok {
					out = append(out, fmt.Sprint(v))
				}
			}
		case "host-lines":
			out = append(out, hostOnly(line))
		default: // lines
			out = append(out, line)
		}
	}
	return out
}

func subst(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

func parseDur(s string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return def
}

func hostOnly(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s
}
