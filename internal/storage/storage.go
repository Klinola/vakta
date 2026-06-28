// Package storage persists events, alerts, and action runs in SQLite.
package storage

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Klinola/vakta/internal/normalizer"
)

//go:embed schema.sql
var schema string

type DB struct {
	conn          *sql.DB
	retentionDays int
}

// Alert is a row to insert into the alerts table.
type Alert struct {
	RuleID   string
	RuleName string
	Severity string
	EventID  int64
	ActionID string
	Status   string // firing | resolved | suppressed
	Tags     []string
	FiredAt  time.Time
}

// StoredEvent is one row read back from the events table.
type StoredEvent struct {
	ID         int64
	Ts         time.Time
	Host       string
	Source     int
	Type       string
	CgroupID   uint64
	PID        uint32
	PPID       uint32
	UID        uint32
	Comm       string
	Ret        int64
	DetailJSON string
	CreatedAt  time.Time
}

// StoredAlert is one row read back from the alerts table.
type StoredAlert struct {
	ID         int64
	RuleID     string
	RuleName   string
	Severity   string
	EventID    sql.NullInt64
	ActionID   sql.NullString
	Status     string
	Tags       []string
	FiredAt    time.Time
	ResolvedAt sql.NullInt64
}

type EventFilter struct {
	Source *int
	Type   *string
	PID    *uint32
	Since  *time.Time
	Until  *time.Time
	Cursor *int64 // pagination: return rows with id < Cursor
	Limit  int    // 0 = default (500)
}

type AlertFilter struct {
	RuleID   *string
	Severity *string
	Status   *string
	Since    *time.Time
	Cursor   *int64 // pagination: return rows with id < Cursor
	Limit    int    // 0 = default (200)
}

// Open initializes the SQLite database at path with the given retention window.
func Open(path string, retentionDays int) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", path)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sql.Open: %w", err)
	}
	conn.SetMaxOpenConns(1) // SQLite single-writer
	if _, err := conn.Exec(schema); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &DB{conn: conn, retentionDays: retentionDays}, nil
}

func (db *DB) Close() error { return db.conn.Close() }

// InsertEvent stores a normalizer.Event and returns its row id.
func (db *DB) InsertEvent(ctx context.Context, ev normalizer.Event) (int64, error) {
	detail, err := json.Marshal(ev.Detail)
	if err != nil {
		return 0, fmt.Errorf("marshal detail: %w", err)
	}
	res, err := db.conn.ExecContext(ctx, `
		INSERT INTO events
		  (ts, host, source, type, cgroup_id, pid, ppid, uid, comm, ret, detail_json, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		ev.Ts.UnixNano(), ev.Host, int(ev.Source), ev.Type,
		ev.CgroupID, ev.PID, ev.PPID, ev.UID, ev.Comm,
		ev.Ret, string(detail), time.Now().UnixNano())
	if err != nil {
		return 0, fmt.Errorf("insert event: %w", err)
	}
	return res.LastInsertId()
}

// InsertEventsBatch stores a slice of events in a single transaction and
// returns row ids in the same order as input. On any error the transaction
// rolls back and (nil, err) is returned — nothing is persisted.
//
// A single transaction amortizes WAL fsync cost across many inserts; with
// SetMaxOpenConns(1) the DB driver already serializes writers, so wrapping
// in BEGIN ... COMMIT is the cheapest path to higher throughput.
func (db *DB) InsertEventsBatch(ctx context.Context, events []normalizer.Event) ([]int64, error) {
	if len(events) == 0 {
		return nil, nil
	}
	tx, err := db.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO events
		  (ts, host, source, type, cgroup_id, pid, ppid, uid, comm, ret, detail_json, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return nil, fmt.Errorf("prepare events: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	now := time.Now().UnixNano()
	ids := make([]int64, len(events))
	for i, ev := range events {
		detail, err := json.Marshal(ev.Detail)
		if err != nil {
			return nil, fmt.Errorf("marshal detail[%d]: %w", i, err)
		}
		res, err := stmt.ExecContext(ctx,
			ev.Ts.UnixNano(), ev.Host, int(ev.Source), ev.Type,
			ev.CgroupID, ev.PID, ev.PPID, ev.UID, ev.Comm,
			ev.Ret, string(detail), now)
		if err != nil {
			return nil, fmt.Errorf("insert event[%d]: %w", i, err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return nil, fmt.Errorf("lastid[%d]: %w", i, err)
		}
		ids[i] = id
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return ids, nil
}

// InsertAlert stores an alert and returns its row id.
func (db *DB) InsertAlert(ctx context.Context, a Alert) (int64, error) {
	tagsJSON, err := json.Marshal(a.Tags)
	if err != nil {
		return 0, err
	}
	res, err := db.conn.ExecContext(ctx, `
		INSERT INTO alerts
		  (rule_id, rule_name, severity, event_id, action_id, status, tags_json, fired_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		a.RuleID, a.RuleName, a.Severity,
		nullInt64(a.EventID), nullString(a.ActionID),
		a.Status, string(tagsJSON), a.FiredAt.UnixNano())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// InsertAlertsBatch stores a slice of alerts in a single transaction and
// returns row ids in the same order. See InsertEventsBatch rationale.
func (db *DB) InsertAlertsBatch(ctx context.Context, alerts []Alert) ([]int64, error) {
	if len(alerts) == 0 {
		return nil, nil
	}
	tx, err := db.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO alerts
		  (rule_id, rule_name, severity, event_id, action_id, status, tags_json, fired_at)
		VALUES (?,?,?,?,?,?,?,?)`)
	if err != nil {
		return nil, fmt.Errorf("prepare alerts: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	ids := make([]int64, len(alerts))
	for i, a := range alerts {
		tagsJSON, err := json.Marshal(a.Tags)
		if err != nil {
			return nil, fmt.Errorf("marshal tags[%d]: %w", i, err)
		}
		res, err := stmt.ExecContext(ctx,
			a.RuleID, a.RuleName, a.Severity,
			nullInt64(a.EventID), nullString(a.ActionID),
			a.Status, string(tagsJSON), a.FiredAt.UnixNano())
		if err != nil {
			return nil, fmt.Errorf("insert alert[%d]: %w", i, err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return nil, fmt.Errorf("lastid[%d]: %w", i, err)
		}
		ids[i] = id
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return ids, nil
}

// QueryEvents returns up to 500 events matching the filter, newest first.
func (db *DB) QueryEvents(ctx context.Context, f EventFilter) ([]StoredEvent, error) {
	q := `SELECT id, ts, host, source, type, cgroup_id, pid, ppid, uid, comm, ret, detail_json, created_at FROM events WHERE 1=1`
	var args []any
	if f.Source != nil {
		q += " AND source = ?"
		args = append(args, *f.Source)
	}
	if f.Type != nil {
		q += " AND type = ?"
		args = append(args, *f.Type)
	}
	if f.PID != nil {
		q += " AND pid = ?"
		args = append(args, *f.PID)
	}
	if f.Since != nil {
		q += " AND ts >= ?"
		args = append(args, f.Since.UnixNano())
	}
	if f.Until != nil {
		q += " AND ts <= ?"
		args = append(args, f.Until.UnixNano())
	}
	if f.Cursor != nil {
		q += " AND id < ?"
		args = append(args, *f.Cursor)
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	q += fmt.Sprintf(" ORDER BY id DESC LIMIT %d", limit)

	rows, err := db.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []StoredEvent
	for rows.Next() {
		var e StoredEvent
		var tsNs, createdNs int64
		var pid, ppid, uid sql.NullInt64
		var comm sql.NullString
		if err := rows.Scan(&e.ID, &tsNs, &e.Host, &e.Source, &e.Type, &e.CgroupID,
			&pid, &ppid, &uid, &comm, &e.Ret, &e.DetailJSON, &createdNs); err != nil {
			return nil, err
		}
		e.Ts = time.Unix(0, tsNs)
		e.CreatedAt = time.Unix(0, createdNs)
		if pid.Valid {
			e.PID = uint32(pid.Int64)
		}
		if ppid.Valid {
			e.PPID = uint32(ppid.Int64)
		}
		if uid.Valid {
			e.UID = uint32(uid.Int64)
		}
		if comm.Valid {
			e.Comm = comm.String
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// QueryAlerts returns up to 200 alerts matching the filter, newest first.
func (db *DB) QueryAlerts(ctx context.Context, f AlertFilter) ([]StoredAlert, error) {
	q := `SELECT id, rule_id, rule_name, severity, event_id, action_id, status, tags_json, fired_at, resolved_at FROM alerts WHERE 1=1`
	var args []any
	if f.RuleID != nil {
		q += " AND rule_id = ?"
		args = append(args, *f.RuleID)
	}
	if f.Severity != nil {
		q += " AND severity = ?"
		args = append(args, *f.Severity)
	}
	if f.Status != nil {
		q += " AND status = ?"
		args = append(args, *f.Status)
	}
	if f.Since != nil {
		q += " AND fired_at >= ?"
		args = append(args, f.Since.UnixNano())
	}
	if f.Cursor != nil {
		q += " AND id < ?"
		args = append(args, *f.Cursor)
	}
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	q += fmt.Sprintf(" ORDER BY id DESC LIMIT %d", limit)

	rows, err := db.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []StoredAlert
	for rows.Next() {
		var a StoredAlert
		var firedNs int64
		var tagsJSON string
		if err := rows.Scan(&a.ID, &a.RuleID, &a.RuleName, &a.Severity,
			&a.EventID, &a.ActionID, &a.Status, &tagsJSON, &firedNs, &a.ResolvedAt); err != nil {
			return nil, err
		}
		a.FiredAt = time.Unix(0, firedNs)
		if tagsJSON != "" {
			_ = json.Unmarshal([]byte(tagsJSON), &a.Tags)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// InsertActionRun persists an action run. action_runs table; used by playbook.
func (db *DB) InsertActionRun(ctx context.Context, actionID string, alertID int64,
	dryRun bool, status string, stepsJSON []byte, startedAt, finishedAt time.Time) (int64, error) {
	dr := 0
	if dryRun {
		dr = 1
	}
	var fin sql.NullInt64
	if !finishedAt.IsZero() {
		fin = sql.NullInt64{Int64: finishedAt.UnixNano(), Valid: true}
	}
	res, err := db.conn.ExecContext(ctx, `
		INSERT INTO action_runs
		  (action_id, alert_id, dry_run, status, steps_json, started_at, finished_at)
		VALUES (?,?,?,?,?,?,?)`,
		actionID, nullInt64(alertID), dr, status, string(stepsJSON),
		startedAt.UnixNano(), fin)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// StoredActionRun is one row read back from the action_runs table.
type StoredActionRun struct {
	ID         int64
	ActionID   string
	AlertID    sql.NullInt64
	DryRun     bool
	Status     string
	StepsJSON  string
	StartedAt  time.Time
	FinishedAt sql.NullInt64
}

// ActionRunFilter narrows QueryActionRuns results.
type ActionRunFilter struct {
	ActionID *string
	Since    *time.Time
}

// QueryActionRuns returns up to 200 action runs matching the filter, newest first.
func (db *DB) QueryActionRuns(ctx context.Context, f ActionRunFilter) ([]StoredActionRun, error) {
	q := `SELECT id, action_id, alert_id, dry_run, status, steps_json, started_at, finished_at FROM action_runs WHERE 1=1`
	var args []any
	if f.ActionID != nil {
		q += " AND action_id = ?"
		args = append(args, *f.ActionID)
	}
	if f.Since != nil {
		q += " AND started_at >= ?"
		args = append(args, f.Since.UnixNano())
	}
	q += " ORDER BY started_at DESC LIMIT 200"

	rows, err := db.conn.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []StoredActionRun
	for rows.Next() {
		var r StoredActionRun
		var dr int
		var startedNs int64
		if err := rows.Scan(&r.ID, &r.ActionID, &r.AlertID, &dr,
			&r.Status, &r.StepsJSON, &startedNs, &r.FinishedAt); err != nil {
			return nil, err
		}
		r.DryRun = dr == 1
		r.StartedAt = time.Unix(0, startedNs)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Prune deletes events older than retentionDays and resolved alerts older than retentionDays.
// Before deleting events, NULLs any alerts.event_id / action_runs.alert_id references
// to soon-to-be-deleted rows so the alerts/action_runs tables don't carry dangling FKs.
func (db *DB) Prune(ctx context.Context) error {
	cutoff := time.Now().Add(-time.Duration(db.retentionDays) * 24 * time.Hour).UnixNano()

	// Null out alerts.event_id pointing at events about to be deleted.
	if _, err := db.conn.ExecContext(ctx,
		`UPDATE alerts SET event_id = NULL WHERE event_id IN (SELECT id FROM events WHERE ts < ?)`,
		cutoff); err != nil {
		return err
	}
	// Null out action_runs.alert_id pointing at alerts about to be deleted.
	if _, err := db.conn.ExecContext(ctx,
		`UPDATE action_runs SET alert_id = NULL WHERE alert_id IN (SELECT id FROM alerts WHERE status = 'resolved' AND resolved_at < ?)`,
		cutoff); err != nil {
		return err
	}
	if _, err := db.conn.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, cutoff); err != nil {
		return err
	}
	if _, err := db.conn.ExecContext(ctx,
		`DELETE FROM alerts WHERE status = 'resolved' AND resolved_at < ?`, cutoff); err != nil {
		return err
	}
	if _, err := db.conn.ExecContext(ctx,
		`DELETE FROM action_runs WHERE finished_at IS NOT NULL AND finished_at < ?`, cutoff); err != nil {
		return err
	}
	return nil
}

// CountEvents returns the total event row count. Used by /api/v1/stats so the
// API doesn't conflate "matched the LIMIT 500 page" with "actual count".
func (db *DB) CountEvents(ctx context.Context) (int64, error) {
	var n int64
	err := db.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&n)
	return n, err
}

// CountAlerts returns the total alert row count.
func (db *DB) CountAlerts(ctx context.Context) (int64, error) {
	var n int64
	err := db.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&n)
	return n, err
}

// CountActionRuns returns the total action_runs row count.
func (db *DB) CountActionRuns(ctx context.Context) (int64, error) {
	var n int64
	err := db.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM action_runs`).Scan(&n)
	return n, err
}

func nullInt64(v int64) sql.NullInt64 {
	if v == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: v, Valid: true}
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
