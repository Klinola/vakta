// Package hub provides the HTTP ingest server used by the vakta hub to receive
// events from forwarder-mode agents.
package hub

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/Klinola/vakta/internal/ingest"
	"github.com/Klinola/vakta/internal/normalizer"
)

// Server listens for ingest POSTs from agents and pushes received events into
// the channel provided at construction time.
type Server struct {
	addr string
	out  chan<- normalizer.Event
	srv  *http.Server
}

// New creates a Server that will push received events into out. out should be a
// buffered channel; the hub event loop reads from it.
func New(addr string, out chan<- normalizer.Event) *Server {
	s := &Server{addr: addr, out: out}
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s
}

// NewHandler returns just the HTTP handler that pushes received events into
// out. Exposed so tests can wrap it in an httptest.Server.
func NewHandler(out chan<- normalizer.Event) http.Handler {
	s := &Server{out: out}
	return s.handler()
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ingest/v1/events", s.handleEvents)
	mux.HandleFunc("GET /ingest/v1/health", s.handleHealth)
	return mux
}

// Start blocks until the server stops (returns http.ErrServerClosed on clean
// shutdown).
func (s *Server) Start() error {
	slog.Info("hub: ingest listening", "addr", s.addr)
	return s.srv.ListenAndServe()
}

// Close shuts the server down.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.srv.Shutdown(ctx)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Addr returns the listening address (useful in tests when addr is ":0").
func (s *Server) Addr() string {
	return s.srv.Addr
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	defer func() { _ = r.Body.Close() }()
	var req ingest.IngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("hub: decode ingest", "err", err)
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	accepted := 0
	dropped := 0
	for _, we := range req.Events {
		ev, err := ingest.FromWire(we)
		if err != nil {
			slog.Warn("hub: from-wire", "err", err, "detail_type", we.DetailType)
			continue
		}
		// Block up to 100ms so a mid-flush dispatcher doesn't trigger drops
		// during normal load; only truly overloaded hubs lose events.
		blockCtx, blockCancel := context.WithTimeout(r.Context(), 100*time.Millisecond)
		select {
		case s.out <- ev:
			accepted++
		case <-blockCtx.Done():
			dropped++
		}
		blockCancel()
	}
	if dropped > 0 {
		slog.Warn("hub: ingest channel full, dropped events", "dropped", dropped, "accepted", accepted)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
