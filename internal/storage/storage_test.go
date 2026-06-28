package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Klinola/vakta/internal/normalizer"
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

func TestInsertEventsBatch_RoundTrip(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	const n = 50
	events := make([]normalizer.Event, n)
	base := time.Now()
	for i := range events {
		events[i] = normalizer.Event{
			Ts:     base.Add(time.Duration(i) * time.Millisecond),
			Source: normalizer.SourceEBPF,
			Type:   "EXEC",
			Host:   "h1",
			PID:    uint32(1000 + i),
			Comm:   "bash",
			Detail: &normalizer.ExecDetail{Filename: "/bin/ls"},
		}
	}

	ids, err := db.InsertEventsBatch(ctx, events)
	if err != nil {
		t.Fatalf("InsertEventsBatch: %v", err)
	}
	if len(ids) != n {
		t.Fatalf("len(ids)=%d want %d", len(ids), n)
	}
	for i := 1; i < n; i++ {
		if ids[i] <= ids[i-1] {
			t.Fatalf("ids not monotonically increasing: %v", ids)
		}
	}

	got, err := db.QueryEvents(ctx, EventFilter{})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(got) != n {
		t.Fatalf("len(got)=%d want %d", len(got), n)
	}
}

func TestInsertEventsBatch_Empty(t *testing.T) {
	db := newDB(t)
	ids, err := db.InsertEventsBatch(context.Background(), nil)
	if err != nil || ids != nil {
		t.Fatalf("empty batch should be no-op, got ids=%v err=%v", ids, err)
	}
}

func TestInsertAlertsBatch_RoundTrip(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	const n = 10
	alerts := make([]Alert, n)
	for i := range alerts {
		alerts[i] = Alert{
			RuleID:   "rule-x",
			RuleName: "Test rule",
			Severity: "P1",
			EventID:  int64(i + 1),
			Status:   "firing",
			Tags:     []string{"test"},
			FiredAt:  time.Now(),
		}
	}

	ids, err := db.InsertAlertsBatch(ctx, alerts)
	if err != nil {
		t.Fatalf("InsertAlertsBatch: %v", err)
	}
	if len(ids) != n {
		t.Fatalf("len(ids)=%d want %d", len(ids), n)
	}

	got, err := db.QueryAlerts(ctx, AlertFilter{})
	if err != nil {
		t.Fatalf("QueryAlerts: %v", err)
	}
	if len(got) != n {
		t.Fatalf("len(got)=%d want %d", len(got), n)
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
