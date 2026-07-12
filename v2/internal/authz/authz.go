// Package authz is the multi-identity authorization comparator — Tyrion's
// signature capability. It replays one request as several identities
// (anonymous, low-priv, admin) and decides whether the endpoint is missing an
// authorization check (BFLA / broken access control), with a confidence score.
package authz

import (
	"sort"
	"strings"

	"github.com/0xyoussef404/tyrion/internal/httpx"
	"github.com/0xyoussef404/tyrion/internal/intel"
	"github.com/0xyoussef404/tyrion/internal/model"
)

// Request is the request to replay across identities.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// IdentityResult captures one identity's response.
type IdentityResult struct {
	Identity  string `json:"identity"`
	Privilege int    `json:"privilege"`
	Status    int    `json:"status"`
	Length    int    `json:"length"`
	BodyHash  string `json:"body_hash"`
	Snippet   string `json:"snippet"`
}

// Report is the comparator's verdict for one request.
type Report struct {
	Request    Request          `json:"-"`
	Method     string           `json:"method"`
	URL        string           `json:"url"`
	Results    []IdentityResult `json:"results"`
	Verdict    string           `json:"verdict"` // ok | potential-bfla | potential-idor
	Confidence int              `json:"confidence"`
	Reason     string           `json:"reason"`
}

// Compare replays req across identities and evaluates access control.
func Compare(client *httpx.Client, req Request, ids []*model.Identity) (*Report, error) {
	rep := &Report{Request: req, Method: req.Method, URL: req.URL, Verdict: "ok"}
	// Ensure a stable order: lowest privilege first.
	sort.Slice(ids, func(i, j int) bool { return ids[i].Privilege < ids[j].Privilege })

	for _, id := range ids {
		headers := map[string]string{}
		for k, v := range req.Headers {
			headers[k] = v
		}
		for k, v := range id.Headers {
			headers[k] = v
		}
		if len(id.Cookies) > 0 {
			headers["Cookie"] = cookieHeader(id.Cookies)
		}
		var body *strings.Reader
		if req.Body != "" {
			body = strings.NewReader(req.Body)
		}
		var resp *httpx.Response
		var err error
		if body != nil {
			resp, err = client.Do(req.Method, req.URL, headers, body, id.Name)
		} else {
			resp, err = client.Do(req.Method, req.URL, headers, nil, id.Name)
		}
		if err != nil {
			rep.Results = append(rep.Results, IdentityResult{Identity: id.Name, Privilege: id.Privilege, Status: -1})
			continue
		}
		rep.Results = append(rep.Results, IdentityResult{
			Identity:  id.Name,
			Privilege: id.Privilege,
			Status:    resp.Status,
			Length:    len(resp.Body),
			BodyHash:  resp.BodyHash(),
			Snippet:   snippet(resp.Body, 160),
		})
	}
	assess(rep)
	return rep, nil
}

// assess implements the decision logic and confidence scoring.
func assess(rep *Report) {
	if len(rep.Results) < 2 {
		return
	}
	// Find the highest-privilege successful result as the "authorized baseline".
	var admin *IdentityResult
	for i := range rep.Results {
		r := &rep.Results[i]
		if success(r.Status) && (admin == nil || r.Privilege > admin.Privilege) {
			admin = r
		}
	}
	if admin == nil {
		return
	}
	mutating := isMutating(rep.Method)
	for i := range rep.Results {
		r := &rep.Results[i]
		if r.Privilege >= admin.Privilege || !success(r.Status) {
			continue
		}
		// A lower-privilege identity got a successful response that closely
		// matches the admin response -> likely missing authorization.
		conf := 40
		reasons := []string{}
		if r.Status == admin.Status {
			conf += 15
			reasons = append(reasons, "same status as admin")
		}
		if r.BodyHash == admin.BodyHash {
			conf += 30
			reasons = append(reasons, "identical body to admin")
		} else if sim := intel.Similarity(r.Snippet, admin.Snippet); sim > 0.6 {
			conf += 20
			reasons = append(reasons, "body highly similar to admin")
		} else if closeLen(r.Length, admin.Length) {
			conf += 10
			reasons = append(reasons, "similar content length to admin")
		}
		if r.Privilege == 0 {
			conf += 10
			reasons = append(reasons, "reachable anonymously")
		}
		if mutating {
			conf += 5
			reasons = append(reasons, "mutating method")
		}
		if conf > 98 {
			conf = 98
		}
		if conf >= rep.Confidence {
			rep.Confidence = conf
			rep.Verdict = "potential-bfla"
			rep.Reason = r.Identity + ": " + strings.Join(reasons, ", ")
		}
	}
}

func success(s int) bool { return s >= 200 && s < 300 }
func isMutating(m string) bool {
	switch strings.ToUpper(m) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

func closeLen(a, b int) bool {
	if a == 0 || b == 0 {
		return a == b
	}
	d := a - b
	if d < 0 {
		d = -d
	}
	return float64(d)/float64(max(a, b)) < 0.1
}

func cookieHeader(c map[string]string) string {
	var parts []string
	for k, v := range c {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func snippet(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		s = s[:n]
	}
	return s
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
