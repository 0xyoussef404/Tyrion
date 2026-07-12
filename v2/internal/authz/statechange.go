package authz

import (
	"strings"

	"github.com/0xyoussef404/tyrion/internal/httpx"
	"github.com/0xyoussef404/tyrion/internal/model"
)

// StateResult reports whether a mutating request actually changed server state.
// This is what turns a finding from "potential" (200 OK) into "confirmed".
type StateResult struct {
	Changed bool
	Before  string
	After   string
	Note    string
}

// VerifyStateChange performs read-before → mutate → read-after as one identity
// and diffs the read responses. A change in the read body is strong evidence
// the mutation took effect (e.g. a role really flipped from User to Admin).
func VerifyStateChange(client *httpx.Client, mutate, read Request, id *model.Identity) StateResult {
	hdr := mergedHeaders(read, id)
	before, err := client.Do(read.Method, read.URL, hdr, nil, "state-before:"+id.Name)
	if err != nil {
		return StateResult{Note: "read-before failed: " + err.Error()}
	}

	mh := mergedHeaders(mutate, id)
	var body *strings.Reader
	if mutate.Body != "" {
		body = strings.NewReader(mutate.Body)
	}
	if body != nil {
		client.Do(mutate.Method, mutate.URL, mh, body, "state-mutate:"+id.Name)
	} else {
		client.Do(mutate.Method, mutate.URL, mh, nil, "state-mutate:"+id.Name)
	}

	// The read cache would return the stale body; force a fresh read by using a
	// distinct identity tag so the cache key differs.
	after, err := client.Do(read.Method, read.URL, hdr, nil, "state-after:"+id.Name)
	if err != nil {
		return StateResult{Note: "read-after failed: " + err.Error()}
	}

	res := StateResult{
		Before: snippet(before.Body, 200),
		After:  snippet(after.Body, 200),
	}
	if before.BodyHash() != after.BodyHash() {
		res.Changed = true
		res.Note = "read response changed after mutation (state confirmed)"
	} else {
		res.Note = "read response unchanged (mutation not confirmed)"
	}
	return res
}

func mergedHeaders(req Request, id *model.Identity) map[string]string {
	h := map[string]string{}
	for k, v := range req.Headers {
		h[k] = v
	}
	for k, v := range id.Headers {
		h[k] = v
	}
	if len(id.Cookies) > 0 {
		h["Cookie"] = cookieHeader(id.Cookies)
	}
	return h
}
