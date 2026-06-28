package loki

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Klinola/vakta/internal/normalizer"
)

func TestPushBuffersAndFlushesOnInterval(t *testing.T) {
	var (
		mu       sync.Mutex
		gotCount int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		streams := body["streams"].([]any)
		mu.Lock()
		for _, s := range streams {
			vals := s.(map[string]any)["values"].([]any)
			gotCount += len(vals)
		}
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(srv.URL, 50*time.Millisecond, 1000)
	defer c.Close()
	for i := 0; i < 5; i++ {
		c.Push(normalizer.Event{Type: "EXEC", Host: "h", Ts: time.Now()})
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if gotCount != 5 {
		t.Fatalf("flushed %d, want 5", gotCount)
	}
	st := c.Stats()
	if st.Flushed != 5 {
		t.Fatalf("stats.Flushed=%d", st.Flushed)
	}
}

func TestPushDropsWhenBufferFull(t *testing.T) {
	// Server blocks until request context is cancelled (force-killed below).
	// Never returning from the handler lets the loki client's buffer fill so
	// subsequent Pushes drop.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer func() {
		srv.CloseClientConnections() // force-kill in-flight before Close blocks
		srv.Close()
	}()
	c := newClientWithBufferCap(srv.URL, 24*time.Hour, 1000, 3) // tiny cap
	defer c.Close()
	for i := 0; i < 50; i++ {
		c.Push(normalizer.Event{Type: "EXEC"})
	}
	st := c.Stats()
	if st.Dropped == 0 {
		t.Fatalf("expected drops, stats=%+v", st)
	}
}
