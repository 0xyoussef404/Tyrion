// Package notify sends events to an outbound webhook (Slack/Discord/generic
// compatible). It is best-effort and never blocks the pipeline on failure.
package notify

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

// Notifier posts messages to a webhook URL. A zero/empty URL disables it.
type Notifier struct {
	URL    string
	client *http.Client
}

// New returns a notifier (no-op if url is empty).
func New(url string) *Notifier {
	return &Notifier{URL: url, client: &http.Client{Timeout: 8 * time.Second}}
}

// Enabled reports whether notifications will actually be sent.
func (n *Notifier) Enabled() bool { return n != nil && n.URL != "" }

// Send posts a title + body. Payload uses the common {"text": ...} shape that
// Slack, Discord (content), and most generic webhooks accept.
func (n *Notifier) Send(title, body string) {
	if !n.Enabled() {
		return
	}
	msg := title
	if body != "" {
		msg += "\n" + body
	}
	payload, _ := json.Marshal(map[string]string{"text": msg, "content": msg})
	req, err := http.NewRequest("POST", n.URL, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if resp, err := n.client.Do(req); err == nil {
		resp.Body.Close()
	}
}
