// Package httpx is the shared HTTP service. Every module that needs to make a
// request goes through one client so we get a single cookie jar, one response
// cache, per-host rate limiting, and backoff — instead of each checker
// re-requesting the same URL.
package httpx

import (
	"crypto/sha1"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"
)

// Response is a captured HTTP response.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
	URL    string
}

// Client wraps net/http with rate limiting and a response cache.
type Client struct {
	hc        *http.Client
	perHost   time.Duration // min interval between requests to one host
	lastHit   map[string]time.Time
	cache     map[string]*Response
	mu        sync.Mutex
	UserAgent string
	MaxBody   int64
}

// New builds a client. perHostRPS is requests-per-second cap per host (<=0 = unlimited).
func New(perHostRPS float64, timeout time.Duration) *Client {
	jar, _ := cookiejar.New(nil)
	var interval time.Duration
	if perHostRPS > 0 {
		interval = time.Duration(float64(time.Second) / perHostRPS)
	}
	return &Client{
		hc: &http.Client{
			Jar:     jar,
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		perHost:   interval,
		lastHit:   map[string]time.Time{},
		cache:     map[string]*Response{},
		UserAgent: "Tyrion/2.0 (+recon)",
		MaxBody:   2 << 20, // 2 MiB
	}
}

// Do performs a request with rate limiting. GET responses are cached by
// method+url+identity so repeated probes reuse the body.
func (c *Client) Do(method, url string, headers map[string]string, body io.Reader, identity string) (*Response, error) {
	ck := cacheKey(method, url, identity)
	if method == http.MethodGet && body == nil {
		c.mu.Lock()
		if r, ok := c.cache[ck]; ok {
			c.mu.Unlock()
			return r, nil
		}
		c.mu.Unlock()
	}

	c.throttle(hostOf(url))

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.doWithBackoff(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, c.MaxBody))
	out := &Response{Status: resp.StatusCode, Header: resp.Header, Body: b, URL: url}

	if method == http.MethodGet && body == nil {
		c.mu.Lock()
		c.cache[ck] = out
		c.mu.Unlock()
	}
	return out, nil
}

// doWithBackoff retries on 429/503 with exponential backoff (circuit-breaker-lite).
func (c *Client) doWithBackoff(req *http.Request) (*http.Response, error) {
	var lastErr error
	delay := 500 * time.Millisecond
	for attempt := 0; attempt < 4; attempt++ {
		resp, err := c.hc.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(delay)
			delay *= 2
			continue
		}
		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			resp.Body.Close()
			time.Sleep(delay)
			delay *= 2
			continue
		}
		return resp, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	// Return the last throttled response rather than nil.
	return c.hc.Do(req)
}

func (c *Client) throttle(host string) {
	if c.perHost <= 0 {
		return
	}
	c.mu.Lock()
	last := c.lastHit[host]
	wait := time.Until(last.Add(c.perHost))
	c.lastHit[host] = time.Now().Add(maxDur(wait, 0))
	c.mu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}

func cacheKey(method, url, identity string) string {
	h := sha1.Sum([]byte(method + "\x00" + url + "\x00" + identity))
	return hex.EncodeToString(h[:])
}

func hostOf(url string) string {
	s := url
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s
}

func maxDur(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// BodyHash returns a stable hash of a response body (for change detection).
func (r *Response) BodyHash() string {
	h := sha1.Sum(r.Body)
	return hex.EncodeToString(h[:])
}
