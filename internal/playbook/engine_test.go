package playbook

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vakta-project/vakta/internal/alertmanager"
	"github.com/vakta-project/vakta/internal/engine"
	"github.com/vakta-project/vakta/internal/normalizer"
	"github.com/vakta-project/vakta/internal/storage"
)

func setup(t *testing.T) (*Engine, *storage.DB) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(`
actions:
  - id: notify-only
    name: Just notify
    steps:
      - id: s1
        action: notify
        params:
          severity: high
          message: "{{ .event.comm }} did a thing"
  - id: with-dry-run
    name: dry
    dry_run: true
    steps:
      - id: s1
        action: notify
        params:
          severity: warning
          message: x
  - id: skip-step
    name: skip
    steps:
      - id: s1
        action: notify
        params: { severity: info, message: hi }
        condition: event.uid == 9999
`), 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(filepath.Join(t.TempDir(), "x.db"), 30)
	if err != nil {
		t.Fatal(err)
	}
	am := alertmanager.New("", time.Second) // empty URL → no-op
	e, err := New([]string{dir}, db, am, EngineOptions{AllowExecRun: false, DryRunGlobal: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e, db
}

func makeMatch(actionID string) engine.Match {
	return engine.Match{
		Rule:  engine.Rule{ID: "r1", Name: "R1", Severity: "info", ActionID: actionID},
		Event: normalizer.Event{Type: "EXEC", PID: 99, UID: 1000, Comm: "ls"},
		At:    time.Now(),
	}
}

func TestRunNotify(t *testing.T) {
	e, _ := setup(t)
	defer e.Close()
	run, err := e.Run(context.Background(), "notify-only", makeMatch("notify-only"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if run.Status != "completed" || len(run.Steps) != 1 {
		t.Fatalf("run=%+v", run)
	}
	if run.Steps[0].Skipped {
		t.Fatal("unexpected skip")
	}
}

func TestRunSkipsStepByCondition(t *testing.T) {
	e, _ := setup(t)
	defer e.Close()
	run, _ := e.Run(context.Background(), "skip-step", makeMatch("skip-step"))
	if !run.Steps[0].Skipped {
		t.Fatalf("step should be skipped; run=%+v", run)
	}
}

func TestRunDryRunMarksSteps(t *testing.T) {
	e, _ := setup(t)
	defer e.Close()
	run, _ := e.Run(context.Background(), "with-dry-run", makeMatch("with-dry-run"))
	if !run.DryRun || run.Status != "completed" {
		t.Fatalf("run=%+v", run)
	}
}

func TestExecRunBlockedByDefault(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "e.yaml"), []byte(`
actions:
  - id: shell
    name: Shell
    steps:
      - id: s1
        action: exec.run
        params: { command: "echo hi" }
`), 0o644)
	db, _ := storage.Open(filepath.Join(t.TempDir(), "x.db"), 30)
	am := alertmanager.New("", time.Second)
	e, err := New([]string{dir}, db, am, EngineOptions{AllowExecRun: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close()
	run, _ := e.Run(context.Background(), "shell", makeMatch("shell"))
	if run.Status != "failed" {
		t.Fatalf("exec.run should be blocked; got %+v", run)
	}
}

func TestUnknownActionReturnsError(t *testing.T) {
	e, _ := setup(t)
	defer e.Close()
	_, err := e.Run(context.Background(), "nope", makeMatch("nope"))
	if err == nil {
		t.Fatal("expected error")
	}
}
