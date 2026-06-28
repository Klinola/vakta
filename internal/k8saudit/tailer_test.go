package k8saudit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write(append(b, '\n'))
	_ = f.Close()

	select {
	case e := <-tl.Entries():
		if e.Verb != "get" || e.Resource != "secrets" || e.Username != "system:apiserver" {
			t.Fatalf("entry=%+v", e)
		}
	case <-ctx.Done():
		t.Fatal("no entry received")
	}
}

func TestTailerSkipsErrorStatuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	bad := `{"verb":"get","responseStatus":{"code":403}}` + "\n"
	good := `{"verb":"get","objectRef":{"resource":"pods"},"responseStatus":{"code":200},"requestReceivedTimestamp":"2026-01-01T00:00:00Z"}` + "\n"
	if err := os.WriteFile(path, []byte(bad+good), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tl, err := New(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	select {
	case e := <-tl.Entries():
		if e.Resource != "pods" {
			t.Fatalf("expected pods entry, got %+v", e)
		}
	case <-ctx.Done():
		t.Fatal("no entry")
	}
}
