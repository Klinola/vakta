package main

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Klinola/vakta/internal/alertmanager"
	"github.com/Klinola/vakta/internal/api"
	"github.com/Klinola/vakta/internal/engine"
	"github.com/Klinola/vakta/internal/normalizer"
	"github.com/Klinola/vakta/internal/storage"
)

// hubTestRig wires the smallest dependencies needed to exercise the
// dispatcher / flushBatch code path against a real SQLite + real engine.
type hubTestRig struct {
	store *storage.DB
	eng   *engine.Engine
	am    *alertmanager.Client
	bus   *api.EventBus
}

func newHubTestRig(t *testing.T) *hubTestRig {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "hub-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	store, err := storage.Open(f.Name(), 1)
	if err != nil {
		t.Fatal("storage:", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	eng, err := engine.New(nil) // built-in rules
	if err != nil {
		t.Fatal("engine:", err)
	}
	// am with empty URL is a no-op client (alertmanager.New documents this).
	am := alertmanager.New("", time.Second)
	bus := api.NewEventBus()
	return &hubTestRig{store: store, eng: eng, am: am, bus: bus}
}

// makeBenignEvents returns events that don't trigger any rule, so flushBatch's
// insert/eval path runs cleanly without alert/playbook side effects.
func makeBenignEvents(n int) []normalizer.Event {
	out := make([]normalizer.Event, n)
	base := time.Now()
	for i := range out {
		out[i] = normalizer.Event{
			Ts:     base.Add(time.Duration(i) * time.Microsecond),
			Source: normalizer.SourceEBPF,
			Type:   "EXEC",
			Host:   "test-node",
			PID:    uint32(10000 + i),
			Comm:   "vakta-bench", // not in any rule keyword set
			Detail: &normalizer.ExecDetail{Filename: "/usr/local/bin/vakta-bench"},
		}
	}
	return out
}

func TestFlushBatch_PersistsAllEvents(t *testing.T) {
	r := newHubTestRig(t)
	ctx := context.Background()
	events := makeBenignEvents(50)

	flushBatch(ctx, events, r.store, r.eng, r.am, nil, r.bus, "test")

	got, err := r.store.QueryEvents(ctx, storage.EventFilter{})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(got) != 50 {
		t.Fatalf("got %d events, want 50", len(got))
	}
}

func TestRunHubDispatcher_BatchesAndFlushes(t *testing.T) {
	r := newHubTestRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eventCh := make(chan normalizer.Event, hubEventChannelBuffer)

	done := make(chan struct{})
	go func() {
		defer close(done)
		runHubDispatcher(ctx, eventCh, r.store, r.eng, r.am, nil, r.bus, "test")
	}()

	const n = 250
	for _, ev := range makeBenignEvents(n) {
		eventCh <- ev
	}

	// Wait for the dispatcher to drain — at hubBatchSize=100 + 100ms interval,
	// 250 events flush in 3 batches (worst case ~300ms). Poll up to 3s.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, err := r.store.QueryEvents(ctx, storage.EventFilter{})
		if err != nil {
			t.Fatalf("QueryEvents: %v", err)
		}
		if len(got) >= n {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatcher did not exit after cancel")
	}

	got, _ := r.store.QueryEvents(context.Background(), storage.EventFilter{})
	if len(got) != n {
		t.Fatalf("after sync, got %d events, want %d", len(got), n)
	}
}

func TestRunHubDispatcher_DrainsOnShutdown(t *testing.T) {
	r := newHubTestRig(t)
	ctx, cancel := context.WithCancel(context.Background())

	eventCh := make(chan normalizer.Event, hubEventChannelBuffer)

	// Pre-load 30 events; smaller than hubBatchSize (100) so they all sit in
	// the partial batch when we cancel before the first ticker fires.
	for _, ev := range makeBenignEvents(30) {
		eventCh <- ev
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		runHubDispatcher(ctx, eventCh, r.store, r.eng, r.am, nil, r.bus, "test")
	}()

	// Give dispatcher a moment to consume the pre-loaded events into its
	// in-memory batch, but cancel BEFORE the 100ms ticker fires.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatcher did not exit after cancel")
	}

	got, _ := r.store.QueryEvents(context.Background(), storage.EventFilter{})
	if len(got) != 30 {
		t.Fatalf("drain path lost events: got %d, want 30", len(got))
	}
}

// TestIngestThroughput_MinimalDrops verifies the dispatcher absorbs a bursty
// feed without dropping events on the way to SQLite. Sized to N=400 so the
// result fits in QueryEvents' 500-row return cap.
func TestIngestThroughput_MinimalDrops(t *testing.T) {
	r := newHubTestRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eventCh := make(chan normalizer.Event, hubEventChannelBuffer)
	go runHubDispatcher(ctx, eventCh, r.store, r.eng, r.am, nil, r.bus, "test")

	const n = 400
	var consumed atomic.Int64
	events := makeBenignEvents(n)
	go func() {
		for i := range events {
			select {
			case eventCh <- events[i]:
				consumed.Add(1)
			case <-time.After(200 * time.Millisecond):
				// dropped
			}
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, _ := r.store.QueryEvents(ctx, storage.EventFilter{Limit: 500})
		if len(got) >= n*9/10 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	got, _ := r.store.QueryEvents(ctx, storage.EventFilter{Limit: 500})
	if len(got) < n*9/10 {
		t.Fatalf("throughput too low: got %d / %d (consumed=%d)", len(got), n, consumed.Load())
	}
}
