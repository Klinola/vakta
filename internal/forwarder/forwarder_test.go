package forwarder

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Klinola/vakta/internal/ingest"
	"github.com/Klinola/vakta/internal/normalizer"
)

func TestForwarderBatchesAndPosts(t *testing.T) {
	var (
		mu       sync.Mutex
		received []ingest.WireEvent
	)
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ingest/v1/events" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req ingest.IngestRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		received = append(received, req.Events...)
		got := len(received)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		if got >= 3 {
			select {
			case <-done:
			default:
				close(done)
			}
		}
	}))
	defer srv.Close()

	f := New(srv.URL, 2, 50*time.Millisecond, 2*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		f.Run(ctx)
	}()

	for i := 0; i < 3; i++ {
		f.Send(ctx, normalizer.Event{
			ID:   uint64(i + 1),
			Ts:   time.Now(),
			Type: "exec",
			Host: "node-1",
			Detail: &normalizer.ExecDetail{
				Filename: "/bin/sh",
				Argv:     []string{"sh"},
			},
		})
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive 3 events within timeout")
	}

	cancel()
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("forwarder.Run did not return after context cancel")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) < 3 {
		t.Fatalf("received %d events, want >= 3", len(received))
	}
	for i, w := range received[:3] {
		if w.ID != uint64(i+1) {
			t.Errorf("event %d: ID=%d want %d", i, w.ID, i+1)
		}
		if w.DetailType != "exec" {
			t.Errorf("event %d: DetailType=%q want exec", i, w.DetailType)
		}
	}
}

func TestForwarderRetriesOnceWhenFirstAttemptFails(t *testing.T) {
	// First POST gets reset (simulates kube-proxy with empty endpoint), second
	// must succeed. Verifies the single-retry behavior covers the hub Service
	// switchover window without dropping the batch.
	var (
		mu       sync.Mutex
		attempts int
		received []ingest.WireEvent
	)
	gotSecond := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n == 1 {
			// Simulate connection reset / 503 from a not-ready hub.
			http.Error(w, "service not ready", http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req ingest.IngestRequest
		_ = json.Unmarshal(body, &req)
		mu.Lock()
		received = append(received, req.Events...)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		select {
		case <-gotSecond:
		default:
			close(gotSecond)
		}
	}))
	defer srv.Close()

	// Speed the retry up for the test (default 500 ms is too slow).
	orig := retryDelay
	retryDelay = 10 * time.Millisecond
	defer func() { retryDelay = orig }()

	f := New(srv.URL, 1, 20*time.Millisecond, 2*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan struct{})
	go func() { defer close(runDone); f.Run(ctx) }()

	f.Send(ctx, normalizer.Event{ID: 42, Type: "exec"})

	select {
	case <-gotSecond:
	case <-time.After(2 * time.Second):
		t.Fatal("retry did not deliver event within 2s")
	}

	cancel()
	<-runDone

	mu.Lock()
	defer mu.Unlock()
	if attempts < 2 {
		t.Fatalf("expected at least 2 attempts (1 fail + 1 retry), got %d", attempts)
	}
	if len(received) == 0 || received[0].ID != 42 {
		t.Fatalf("expected event ID=42 delivered on retry, received=%+v", received)
	}
}

func TestForwarderSendBlocksThenContextEscapes(t *testing.T) {
	// Send is now blocking (backpressure semantics). Verify it actually blocks
	// when the buffer is full, and unblocks when the caller's context is
	// cancelled — so shutdown is never held up by a stalled hub.
	f := New("http://127.0.0.1:1", 50, time.Second, 100*time.Millisecond)

	// Don't run f → the in chan never drains. Fill it exactly to capacity.
	bgCtx := context.Background()
	for i := 0; i < sendQueueSize; i++ {
		f.Send(bgCtx, normalizer.Event{ID: uint64(i)})
	}

	// Next Send must block on a full chan, then return when ctx is cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan struct{})
	go func() {
		f.Send(ctx, normalizer.Event{ID: 9999})
		close(doneCh)
	}()

	// Confirm it's actually blocked (not racing through).
	select {
	case <-doneCh:
		t.Fatal("Send returned before ctx cancel — buffer not actually full or not blocking")
	case <-time.After(50 * time.Millisecond):
	}

	cancel()

	select {
	case <-doneCh:
	case <-time.After(time.Second):
		t.Fatal("Send did not return within 1s after ctx cancel")
	}
}
