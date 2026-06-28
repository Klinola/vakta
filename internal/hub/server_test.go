package hub

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Klinola/vakta/internal/ingest"
	"github.com/Klinola/vakta/internal/normalizer"
)

func TestServerReceivesAndDecodes(t *testing.T) {
	ch := make(chan normalizer.Event, 16)
	srv := httptest.NewServer(NewHandler(ch))
	defer srv.Close()

	req := ingest.IngestRequest{
		Events: []ingest.WireEvent{
			ingest.ToWire(normalizer.Event{
				ID: 1, Type: "exec", Host: "n1",
				Detail: &normalizer.ExecDetail{Filename: "/bin/ls", Argv: []string{"ls"}},
			}),
			ingest.ToWire(normalizer.Event{
				ID: 2, Type: "open", Host: "n1",
				Detail: &normalizer.OpenDetail{Path: "/etc/passwd"},
			}),
		},
	}
	body, _ := json.Marshal(req)
	resp, err := http.Post(srv.URL+"/ingest/v1/events", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}

	got := make([]normalizer.Event, 0, 2)
	for i := 0; i < 2; i++ {
		select {
		case ev := <-ch:
			got = append(got, ev)
		case <-time.After(time.Second):
			t.Fatalf("event %d not received", i)
		}
	}
	if got[0].ID != 1 || got[0].Type != "exec" {
		t.Errorf("event 0: %+v", got[0])
	}
	if got[1].ID != 2 || got[1].Type != "open" {
		t.Errorf("event 1: %+v", got[1])
	}
	if d, ok := got[0].Detail.(*normalizer.ExecDetail); !ok || d.Filename != "/bin/ls" {
		t.Errorf("event 0 detail: %#v", got[0].Detail)
	}
	if d, ok := got[1].Detail.(*normalizer.OpenDetail); !ok || d.Path != "/etc/passwd" {
		t.Errorf("event 1 detail: %#v", got[1].Detail)
	}
}

func TestServerHealth(t *testing.T) {
	ch := make(chan normalizer.Event, 1)
	srv := httptest.NewServer(NewHandler(ch))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/ingest/v1/health")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
}

func TestServerRejectsInvalidJSON(t *testing.T) {
	ch := make(chan normalizer.Event, 1)
	srv := httptest.NewServer(NewHandler(ch))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/ingest/v1/events", "application/json", bytes.NewReader([]byte("not json")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
}
