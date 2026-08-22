package k8saudit

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// TestNewOnAbsentLogReportsDisabled pins the fix for the app-4 outage: on a node
// with no API-server audit log the source must decline to start and hand the
// caller an error it can log and move past. It must not block, and it must not
// reach nxadm/tail's inotify setup, whose failure path is os.Exit(1) and would
// take the whole agent with it.
func TestNewOnAbsentLogReportsDisabled(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "logs", "audit.log")

	done := make(chan error, 1)
	go func() {
		tr, err := New(context.Background(), missing)
		if tr != nil {
			_ = tr.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("New succeeded on a path that does not exist; the source must report itself disabled")
		}
		if !errors.Is(err, ErrLogAbsent) {
			t.Fatalf("New error = %v, want one wrapping ErrLogAbsent so callers can tell 'not this node' from a real failure", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("New blocked on a missing audit log — this is the wait-forever behaviour that preceded the crash")
	}
}
