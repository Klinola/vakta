package k8saudit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestTailerSkipsPreexistingContent guards the crash loop on the control-plane
// node: k3s rotates its audit log at 100 MB, and a tailer that opened at byte 0
// read and parsed the whole backlog on startup, OOM-killing the agent within
// seconds — 159 times — and replaying stale audit events on every restart.
func TestTailerSkipsPreexistingContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	backlog, _ := json.Marshal(map[string]any{
		"requestReceivedTimestamp": "2026-01-01T00:00:00Z",
		"verb":                     "delete",
		"objectRef":                map[string]any{"resource": "OLD-BACKLOG"},
		"user":                     map[string]any{"username": "past"},
		"responseStatus":           map[string]any{"code": 200},
	})
	if err := os.WriteFile(path, append(backlog, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tl, err := New(ctx, path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tl.Close()

	fresh, _ := json.Marshal(map[string]any{
		"requestReceivedTimestamp": "2026-01-01T00:00:01Z",
		"verb":                     "get",
		"objectRef":                map[string]any{"resource": "FRESH"},
		"user":                     map[string]any{"username": "now"},
		"responseStatus":           map[string]any{"code": 200},
	})
	e := appendUntilRead(ctx, t, path, append(fresh, '\n'), tl.Entries())
	if e.Resource == "OLD-BACKLOG" {
		t.Fatal("tailer replayed pre-existing content instead of starting at the end of the file")
	}
	if e.Resource != "FRESH" {
		t.Fatalf("entry=%+v", e)
	}
}

func TestTailerParsesNewLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tl, err := New(ctx, path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer tl.Close()

	entry := map[string]any{
		"requestReceivedTimestamp": "2026-01-01T00:00:00Z",
		"verb":                     "get",
		"objectRef": map[string]any{
			"resource": "secrets", "namespace": "kube-system", "name": "ca",
		},
		"user":           map[string]any{"username": "system:apiserver"},
		"sourceIPs":      []string{"10.0.0.1"},
		"responseStatus": map[string]any{"code": 200},
	}
	b, _ := json.Marshal(entry)
	e := appendUntilRead(ctx, t, path, append(b, '\n'), tl.Entries())
	if e.Verb != "get" || e.Resource != "secrets" || e.Username != "system:apiserver" {
		t.Fatalf("entry=%+v", e)
	}
}

func TestTailerSkipsErrorStatuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	bad := `{"verb":"get","responseStatus":{"code":403}}` + "\n"
	good := `{"verb":"get","objectRef":{"resource":"pods"},"responseStatus":{"code":200},"requestReceivedTimestamp":"2026-01-01T00:00:00Z"}` + "\n"
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tl, err := New(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()

	if e := appendUntilRead(ctx, t, path, []byte(bad+good), tl.Entries()); e.Resource != "pods" {
		t.Fatalf("expected pods entry, got %+v", e)
	}
}

// appendUntilRead appends line to path until an entry comes back, and returns
// the first one.
//
// The tailer starts at the end of the file, so a single append racing its
// initial open would be missed — a real audit log is written continuously, a
// test file is not. Retrying also removes a pre-existing flake: these tests
// used to append once immediately after New and fail whenever the tailer had
// not finished opening the file.
func appendUntilRead(ctx context.Context, t *testing.T, path string, line []byte, entries <-chan Entry) Entry {
	t.Helper()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write(line)
		_ = f.Close()

		select {
		case e := <-entries:
			return e
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("no entry received")
		}
	}
}
