package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Klinola/vakta/internal/engine"
	"github.com/Klinola/vakta/internal/normalizer"
	"github.com/Klinola/vakta/internal/storage"
)

func setup(t *testing.T) *Server {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "x.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.InsertEvent(context.Background(), normalizer.Event{
		Ts: time.Now(), Source: normalizer.SourceEBPF, Type: "EXEC",
		Host: "h", PID: 7, Comm: "ls",
	})
	eng, _ := engine.New([]string{t.TempDir()})
	bus := NewEventBus()
	s := New(":0", db, eng, bus, nil, ServerOptions{})
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestGetEvents(t *testing.T) {
	s := setup(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/events", nil)
	s.handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if items, _ := resp["events"].([]any); len(items) != 1 {
		t.Fatalf("events=%v", resp["events"])
	}
}

func TestGetRules(t *testing.T) {
	s := setup(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/rules", nil)
	s.handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestPostRulesReload(t *testing.T) {
	s := setup(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/rules/reload", nil)
	s.handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestBasicAuthEnforced(t *testing.T) {
	db, _ := storage.Open(filepath.Join(t.TempDir(), "x.db"), 30)
	eng, _ := engine.New([]string{t.TempDir()})
	s := New(":0", db, eng, NewEventBus(), nil, ServerOptions{
		Auth: "basic", Username: "u", Password: "p",
	})
	t.Cleanup(func() { _ = s.Close() })

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/events", nil)
	s.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/api/v1/events", nil)
	req.SetBasicAuth("u", "p")
	s.handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}
