// Package alertmanager POSTs vakta alerts to Prometheus Alertmanager.
package alertmanager

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Alert is one outgoing alert in Alertmanager's /api/v2/alerts schema.
type Alert struct {
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt,omitempty"`
	GeneratorURL string            `json:"generatorURL,omitempty"`
}

// Client posts alerts to Alertmanager. baseURL example: http://alertmanager:9093.
type Client struct {
	baseURL string
	http    *http.Client
}

func New(baseURL string, timeout time.Duration) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: timeout},
	}
}

// Send POSTs the alerts asynchronously. Errors are logged, never returned.
func (c *Client) Send(ctx context.Context, alerts []Alert) {
	if len(alerts) == 0 || c.baseURL == "" {
		return
	}
	go c.post(ctx, alerts)
}

// Resolve marks alerts with the given labels as resolved (EndsAt = now).
func (c *Client) Resolve(ctx context.Context, labels map[string]string) {
	if c.baseURL == "" {
		return
	}
	a := Alert{Labels: labels, EndsAt: time.Now()}
	go c.post(ctx, []Alert{a})
}

func (c *Client) post(ctx context.Context, alerts []Alert) {
	body, err := json.Marshal(alerts)
	if err != nil {
		slog.Warn("alertmanager: marshal", "err", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, "POST",
		c.baseURL+"/api/v2/alerts", bytes.NewReader(body))
	if err != nil {
		slog.Warn("alertmanager: new request", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		slog.Warn("alertmanager: POST", "err", err, "url", c.baseURL)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		slog.Warn("alertmanager: bad status", "status", resp.StatusCode)
	}
}
