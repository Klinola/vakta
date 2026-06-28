// Package api serves vakta's REST API, SSE stream, and embedded web UI.
package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"sync"
	"time"

	"github.com/Klinola/vakta/internal/engine"
	"github.com/Klinola/vakta/internal/playbook"
	"github.com/Klinola/vakta/internal/storage"
)

type ServerOptions struct {
	Auth     string // none | basic
	Username string
	Password string
}

type Server struct {
	addr    string
	db      *storage.DB
	eng     *engine.Engine
	pb      *playbook.Engine
	bus     *EventBus
	opts    ServerOptions
	handler http.Handler
	httpSrv *http.Server
	mu      sync.Mutex
	closed  bool
}

func New(addr string, db *storage.DB, eng *engine.Engine, bus *EventBus, pb *playbook.Engine, opts ServerOptions) *Server {
	s := &Server{addr: addr, db: db, eng: eng, pb: pb, bus: bus, opts: opts}
	s.handler = s.buildRouter()
	return s
}

func (s *Server) Start() error {
	s.httpSrv = &http.Server{
		Addr:              s.addr,
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s.httpSrv.ListenAndServe()
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.httpSrv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.httpSrv.Shutdown(ctx)
}

func (s *Server) buildRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/events", s.handleGetEvents)
	mux.HandleFunc("GET /api/v1/events/stream", s.handleEventStream)
	mux.HandleFunc("GET /api/v1/alerts", s.handleGetAlerts)
	mux.HandleFunc("GET /api/v1/rules", s.handleGetRules)
	mux.HandleFunc("POST /api/v1/rules/reload", s.handleReloadRules)
	mux.HandleFunc("POST /api/v1/rules/test", s.handleTestRule)
	mux.HandleFunc("GET /api/v1/actions", s.handleGetActions)
	mux.HandleFunc("GET /api/v1/action-runs", s.handleGetActionRuns)
	mux.HandleFunc("GET /api/v1/stats", s.handleGetStats)
	mux.Handle("/", http.FileServer(http.FS(uiFS())))

	if s.opts.Auth == "basic" {
		return s.basicAuth(mux)
	}
	return mux
}

func (s *Server) basicAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(u), []byte(s.opts.Username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(s.opts.Password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="vakta"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}
