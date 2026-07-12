package engine

import (
	"bufio"
	"os"
	"sync"
)

// FileCache persists cache keys to a file so unchanged work is skipped across
// runs. Keys are typically content fingerprints (dns hash, http hash, ...).
type FileCache struct {
	path string
	mu   sync.Mutex
	keys map[string]bool
}

// OpenCache loads a cache from path (created if absent).
func OpenCache(path string) *FileCache {
	c := &FileCache{path: path, keys: map[string]bool{}}
	fh, err := os.Open(path)
	if err != nil {
		return c
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		if k := sc.Text(); k != "" {
			c.keys[k] = true
		}
	}
	return c
}

// Has reports whether key is cached.
func (c *FileCache) Has(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.keys[key]
}

// Set records key and appends it to the backing file.
func (c *FileCache) Set(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keys[key] {
		return
	}
	c.keys[key] = true
	fh, err := os.OpenFile(c.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer fh.Close()
	fh.WriteString(key + "\n")
}
