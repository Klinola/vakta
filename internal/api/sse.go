package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/vakta-project/vakta/internal/normalizer"
)

// EventBus is a fan-out for live events to SSE subscribers.
// The agent calls Publish for every normalized event.
type EventBus struct {
	mu   sync.Mutex
	subs map[chan normalizer.Event]struct{}
}

// NewEventBus creates a fresh event bus.
func NewEventBus() *EventBus {
	return &EventBus{subs: map[chan normalizer.Event]struct{}{}}
}

// Publish sends an event to all current subscribers without blocking.
// Slow subscribers drop messages.
func (b *EventBus) Publish(ev normalizer.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (b *EventBus) subscribe() (chan normalizer.Event, func()) {
	ch := make(chan normalizer.Event, 64)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
		close(ch)
	}
}

func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, unsubscribe := s.bus.subscribe()
	defer unsubscribe()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			b, _ := json.Marshal(ev)
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
	}
}
