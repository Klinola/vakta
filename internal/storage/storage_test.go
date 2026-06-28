package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/vakta-project/vakta/internal/normalizer"
)

func newDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"), 30)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestInsertAndQueryEvent(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	id, err := db.InsertEvent(ctx, normalizer.Event{
		Ts: time.Now(), Source: normalizer.SourceEBPF, Type: "EXEC",
		Host: "h1", PID: 100, Comm: "ls", Ret: 0,
		Detail: &normalizer.ExecDetail{Filename: "/bin/ls"},
	})
	if err != nil || id <= 0 {
		t.Fatalf("InsertEvent: id=%d err=%v", id, err)
	}
	got, err := db.QueryEvents(ctx, EventFilter{})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(got) != 1 || got[0].Type != "EXEC" || got[0].Comm != "ls" {
		t.Fatalf("got=%+v", got)
	}
}

func TestQueryEventsFilterByType(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	for _, typ := range []string{"EXEC", "CONNECT", "EXEC", "OPEN"} {
		_, _ = db.InsertEvent(ctx, normalizer.Event{Ts: time.Now(), Type: typ, Host: "h"})
	}
	wanted := "EXEC"
	got, _ := db.QueryEvents(ctx, EventFilter{Type: &wanted})
	if len(got) != 2 {
		t.Fatalf("want 2 EXEC events, got %d", len(got))
	}
}

func TestInsertAndQueryAlert(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	id, err := db.InsertAlert(ctx, Alert{
		RuleID: "rule-x", RuleName: "X", Severity: "high",
		EventID: 0, ActionID: "", Status: "firing",
		Tags: []string{"a", "b"}, FiredAt: time.Now(),
	})
	if err != nil || id <= 0 {
		t.Fatalf("InsertAlert: %v", err)
	}
	got, _ := db.QueryAlerts(ctx, AlertFilter{})
	if len(got) != 1 || got[0].RuleID != "rule-x" || len(got[0].Tags) != 2 {
		t.Fatalf("got=%+v", got)
	}
}

func TestInsertAndQueryActionRun(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	stepsJSON := []byte(`[{"ID":"s1","Output":"ok"}]`)
	id, err := db.InsertActionRun(ctx, "act-1", 0, true, "completed",
		stepsJSON, time.Now().Add(-time.Second), time.Now())
	if err != nil || id <= 0 {
		t.Fatalf("InsertActionRun: id=%d err=%v", id, err)
	}
	runs, err := db.QueryActionRuns(ctx, ActionRunFilter{})
	if err != nil {
		t.Fatalf("QueryActionRuns: %v", err)
	}
	if len(runs) != 1 || runs[0].ActionID != "act-1" || !runs[0].DryRun || runs[0].Status != "completed" {
		t.Fatalf("got=%+v", runs)
	}
}

func TestPruneOldEvents(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "p.db"), 1) // 1 day retention
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	old := time.Now().Add(-48 * time.Hour)
	newer := time.Now()
	_, _ = db.InsertEvent(ctx, normalizer.Event{Ts: old, Type: "OLD", Host: "h"})
	_, _ = db.InsertEvent(ctx, normalizer.Event{Ts: newer, Type: "NEW", Host: "h"})
	if err := db.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := db.QueryEvents(ctx, EventFilter{})
	if len(got) != 1 || got[0].Type != "NEW" {
		t.Fatalf("Prune did not remove old: got %+v", got)
	}
}
