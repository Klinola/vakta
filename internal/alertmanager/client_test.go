package alertmanager

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestSendPostsAlerts(t *testing.T) {
	var (
		mu      sync.Mutex
		gotBody []byte
		gotPath string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody = b
		gotPath = r.URL.Path
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(srv.URL, time.Second)
	c.Send(context.Background(), []Alert{{
		Labels:      map[string]string{"alertname": "X", "severity": "high"},
		Annotations: map[string]string{"summary": "test"},
		StartsAt:    time.Now(),
	}})
	// Send is async — wait briefly.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := gotBody != nil
		mu.Unlock()
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotPath != "/api/v2/alerts" {
		t.Fatalf("path=%q", gotPath)
	}
	var parsed []map[string]any
	if err := json.Unmarshal(gotBody, &parsed); err != nil {
		t.Fatalf("body unparseable: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("alerts=%d", len(parsed))
	}
	if parsed[0]["labels"].(map[string]any)["alertname"] != "X" {
		t.Fatalf("labels=%v", parsed[0]["labels"])
	}
}

func TestResolveSetsEndsAt(t *testing.T) {
	var (
		mu      sync.Mutex
		gotBody []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody = b
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := New(srv.URL, time.Second)
	c.Resolve(context.Background(), map[string]string{"alertname": "Y"})
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := gotBody != nil
		mu.Unlock()
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotBody == nil {
		t.Fatal("no request received")
	}
	var parsed []map[string]any
	_ = json.Unmarshal(gotBody, &parsed)
	if parsed[0]["endsAt"] == "" {
		t.Fatal("endsAt empty for Resolve")
	}
}
