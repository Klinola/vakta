// Package forwarder batches normalizer.Events and POSTs them to a hub.
package forwarder

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Klinola/vakta/internal/ingest"
	"github.com/Klinola/vakta/internal/normalizer"
)

const sendQueueSize = 4096

// Forwarder batches normalizer.Events and POSTs them to hubURL/ingest/v1/events.
// When the hub is unreachable: log slog.Warn, drop the batch, continue.
type Forwarder struct {
	endpoint      string
	batchSize     int
	flushInterval time.Duration
	client        *http.Client
	in            chan normalizer.Event
}

// New creates a Forwarder. hubURL is the base URL of the hub (e.g.
// "http://vakta-hub:7070"). batchSize <= 0 falls back to 50. flushInterval
// <= 0 falls back to 500ms. httpTimeout <= 0 falls back to 5s.
func New(hubURL string, batchSize int, flushInterval, httpTimeout time.Duration) *Forwarder {
	if batchSize <= 0 {
		batchSize = 50
	}
	if flushInterval <= 0 {
		flushInterval = 500 * time.Millisecond
	}
	if httpTimeout <= 0 {
		httpTimeout = 5 * time.Second
	}
	endpoint := strings.TrimRight(hubURL, "/") + "/ingest/v1/events"
	return &Forwarder{
		endpoint:      endpoint,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		client:        &http.Client{Timeout: httpTimeout},
		in:            make(chan normalizer.Event, sendQueueSize),
	}
}

// Send queues ev into the internal buffer. Non-blocking: drops + warns if full.
func (f *Forwarder) Send(ev normalizer.Event) {
	select {
	case f.in <- ev:
	default:
		slog.Warn("forwarder: queue full, dropping event", "id", ev.ID, "type", ev.Type)
	}
}

// Run is the background flush loop. Exits when ctx is cancelled, flushing any
// pending events first.
func (f *Forwarder) Run(ctx context.Context) {
	batch := make([]normalizer.Event, 0, f.batchSize)
	ticker := time.NewTicker(f.flushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		f.post(ctx, batch)
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			// Drain any remaining buffered events without blocking.
			for {
				select {
				case ev := <-f.in:
					batch = append(batch, ev)
					if len(batch) >= f.batchSize {
						f.post(context.Background(), batch)
						batch = batch[:0]
					}
				default:
					if len(batch) > 0 {
						f.post(context.Background(), batch)
					}
					return
				}
			}
		case ev := <-f.in:
			batch = append(batch, ev)
			if len(batch) >= f.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (f *Forwarder) post(ctx context.Context, events []normalizer.Event) {
	req := ingest.IngestRequest{Events: make([]ingest.WireEvent, len(events))}
	for i, ev := range events {
		req.Events[i] = ingest.ToWire(ev)
	}
	body, err := json.Marshal(req)
	if err != nil {
		slog.Warn("forwarder: marshal batch", "err", err, "count", len(events))
		return
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint, bytes.NewReader(body))
	if err != nil {
		slog.Warn("forwarder: build request", "err", err)
		return
	}
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(hreq)
	if err != nil {
		slog.Warn("forwarder: post batch", "err", err, "count", len(events))
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		slog.Warn("forwarder: hub rejected batch",
			"status", resp.StatusCode, "count", len(events),
			"err", fmt.Errorf("status=%d", resp.StatusCode))
	}
}
