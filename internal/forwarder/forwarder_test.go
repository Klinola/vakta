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
		f.Send(normalizer.Event{
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

func TestForwarderQueueFullDrops(t *testing.T) {
	// Use a non-existent server; Send must not block when queue fills.
	f := New("http://127.0.0.1:1", 50, time.Second, 100*time.Millisecond)
	// Don't run f — just keep pushing past the buffer to ensure non-blocking.
	for i := 0; i < sendQueueSize+10; i++ {
		f.Send(normalizer.Event{ID: uint64(i)})
	}
}
