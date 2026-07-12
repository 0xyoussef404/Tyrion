package config

import (
	"os"
	"path/filepath"
	"time"

	"github.com/0xyoussef404/tyrion/internal/pluginfmt"
)

// Settings are user defaults loaded from a config file. CLI flags override them.
type Settings struct {
	Profile     string
	Concurrency int
	Timeout     time.Duration
	Outdir      string
	Webhook     string
	// API keys / tokens for tools that use them (exported to the environment).
	Env map[string]string
}

// Defaults returns baseline settings.
func Defaults() Settings {
	return Settings{Profile: "passive", Concurrency: 20, Timeout: 20 * time.Minute, Outdir: ".", Env: map[string]string{}}
}

// Load reads ./tyrion.yaml, then $HOME/.tyrion.yaml (first found wins), applying
// values over the defaults. Missing file is not an error.
func Load() Settings {
	s := Defaults()
	for _, path := range candidatePaths() {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		m, err := pluginfmt.Parse(string(data))
		if err != nil {
			continue
		}
		if v := pluginfmt.String(m, "profile", ""); v != "" {
			s.Profile = v
		}
		if v := pluginfmt.String(m, "concurrency", ""); v != "" {
			if n := atoi(v); n > 0 {
				s.Concurrency = n
			}
		}
		if v := pluginfmt.String(m, "timeout", ""); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				s.Timeout = d
			}
		}
		if v := pluginfmt.String(m, "outdir", ""); v != "" {
			s.Outdir = v
		}
		if v := pluginfmt.String(m, "webhook", ""); v != "" {
			s.Webhook = v
		}
		// Any key under env_* becomes an environment variable for tools.
		for k := range m {
			if len(k) > 4 && k[:4] == "env_" {
				s.Env[k[4:]] = pluginfmt.String(m, k, "")
			}
		}
		break // first file wins
	}
	// Environment always overrides file for the webhook (handy for CI).
	if v := os.Getenv("TYRION_WEBHOOK"); v != "" {
		s.Webhook = v
	}
	return s
}

// ApplyEnv exports configured API keys into the process environment so plugins
// (subfinder, chaos, github-subdomains, ...) can read them.
func (s Settings) ApplyEnv() {
	for k, v := range s.Env {
		if v != "" {
			os.Setenv(k, v)
		}
	}
}

func candidatePaths() []string {
	paths := []string{"tyrion.yaml", "tyrion.yml"}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".tyrion.yaml"), filepath.Join(home, ".tyrion.yml"))
	}
	return paths
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
