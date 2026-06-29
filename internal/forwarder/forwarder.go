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

// sendQueueSize is the per-agent in-chan buffer. Sized to absorb a ~5s burst at
// ~6.5k events/s (e.g. k8s rollout-induced syscall storms) without reaching the
// BPF ringbuf backpressure point. ~16 MB at ~500 B/event.
const sendQueueSize = 32768

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

// Send queues ev into the internal buffer. Blocks when the buffer is full so
// backpressure propagates upstream (normalizer → probe ringbuf reader → BPF
// ringbuf reserve, where the kernel side accumulates atomic drop counters
// instead of userspace flooding logs). Returns early on ctx cancellation so
// shutdown is not held up by a stalled hub.
func (f *Forwarder) Send(ctx context.Context, ev normalizer.Event) {
	select {
	case f.in <- ev:
	case <-ctx.Done():
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

// retryDelay is how long post waits before its single retry attempt. Sized to
// cover the ~1s Service endpoint switchover window during hub Deployment
// rollouts (old endpoint torn down → new pod readiness probe passes → kube-proxy
// picks up the new backend). One retry, not exponential, because if the hub is
// down for longer than that the right answer is upstream backpressure, not
// holding the Run goroutine hostage with longer sleeps. Tests override.
var retryDelay = 500 * time.Millisecond

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

	if err := f.postOnce(ctx, body); err == nil {
		return
	}
	// First attempt failed (network or 5xx). Wait briefly so the Service
	// endpoint can catch up to a restarting hub, then try once more. The
	// first-attempt error is intentionally not logged — the retry almost
	// always succeeds during a rollout, and double-logging adds noise.
	select {
	case <-time.After(retryDelay):
	case <-ctx.Done():
		return
	}
	if err := f.postOnce(ctx, body); err != nil {
		slog.Warn("forwarder: post batch", "err", err, "count", len(events))
	}
}

func (f *Forwarder) postOnce(ctx context.Context, body []byte) error {
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, f.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := f.client.Do(hreq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("status=%d", resp.StatusCode)
	}
	return nil
}
