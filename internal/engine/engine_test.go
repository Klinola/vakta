package engine

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vakta-project/vakta/internal/normalizer"
)

func writeRule(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEngineMatchesSimpleRule(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "x.yaml", `
rules:
  - id: exec-as-root
    name: Exec as root
    severity: high
    event_type: EXEC
    condition: event.uid == 0
    tags: [t1]
`)
	e, err := New([]string{dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ev := normalizer.Event{Type: "EXEC", UID: 0, Ts: time.Now()}
	ms := e.Evaluate(ev)
	if len(ms) != 1 || ms[0].Rule.ID != "exec-as-root" {
		t.Fatalf("matches=%+v", ms)
	}
}

func TestEngineRejectsEventTypeMismatch(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "y.yaml", `
rules:
  - id: r
    name: R
    severity: info
    event_type: CONNECT
    condition: "true"
`)
	e, _ := New([]string{dir})
	ms := e.Evaluate(normalizer.Event{Type: "EXEC"})
	if len(ms) != 0 {
		t.Fatalf("expected no match, got %+v", ms)
	}
}

func TestEngineDetailAccess(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "p.yaml", `
rules:
  - id: connect-suspicious
    name: Connect to suspicious port
    severity: critical
    event_type: CONNECT
    condition: detail.dst_port == 4444
`)
	e, err := New([]string{dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ev := normalizer.Event{
		Type: "CONNECT",
		Detail: &normalizer.ConnectDetail{
			DstIP: netip.MustParseAddr("1.2.3.4"), DstPort: 4444, Family: 2,
		},
	}
	if got := e.Evaluate(ev); len(got) != 1 {
		t.Fatalf("matches=%+v", got)
	}
}

func TestEngineRejectsBadCEL(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "bad.yaml", `
rules:
  - id: bad
    name: Bad
    severity: info
    condition: this is not CEL
`)
	if _, err := New([]string{dir}); err == nil {
		t.Fatal("expected CEL compile error")
	}
}

func TestEngineReload(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "v1.yaml", `
rules:
  - id: r1
    name: R1
    severity: info
    condition: "true"
`)
	e, _ := New([]string{dir})
	if len(e.Rules()) != 1 {
		t.Fatal()
	}
	writeRule(t, dir, "v1.yaml", `
rules:
  - id: r1
    name: R1
    severity: info
    condition: "true"
  - id: r2
    name: R2
    severity: warning
    condition: "true"
`)
	if err := e.Reload(); err != nil {
		t.Fatal(err)
	}
	if len(e.Rules()) != 2 {
		t.Fatalf("after reload got %d rules", len(e.Rules()))
	}
}

func TestEvaluateOrdersBySeverityThenID(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "x.yaml", `
rules:
  - id: bbb
    name: B
    severity: warning
    condition: "true"
  - id: aaa
    name: A
    severity: critical
    condition: "true"
  - id: ccc
    name: C
    severity: critical
    condition: "true"
`)
	e, _ := New([]string{dir})
	ms := e.Evaluate(normalizer.Event{Type: "X"})
	if len(ms) != 3 {
		t.Fatalf("got %d", len(ms))
	}
	if ms[0].Rule.ID != "aaa" || ms[1].Rule.ID != "ccc" || ms[2].Rule.ID != "bbb" {
		t.Fatalf("order wrong: %s %s %s", ms[0].Rule.ID, ms[1].Rule.ID, ms[2].Rule.ID)
	}
}
