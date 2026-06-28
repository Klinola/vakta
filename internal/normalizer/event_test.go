package normalizer

import (
	"net/netip"
	"testing"
	"time"
)

func TestEventZeroValueDefaults(t *testing.T) {
	var e Event
	if e.Source != 0 {
		t.Errorf("Source = %d, want 0", e.Source)
	}
	if e.Detail != nil {
		t.Errorf("Detail = %v, want nil", e.Detail)
	}
}

func TestSourceConstants(t *testing.T) {
	if SourceEBPF != 1 || SourceAuditd != 2 || SourceK8sAudit != 3 {
		t.Fatal("source constants drifted")
	}
}

func TestExecDetail(t *testing.T) {
	d := ExecDetail{Filename: "/bin/ls", Argv: []string{"ls", "-la"}}
	if d.Filename != "/bin/ls" || len(d.Argv) != 2 {
		t.Fatal()
	}
}

func TestConnectDetail(t *testing.T) {
	d := ConnectDetail{
		DstIP:   netip.MustParseAddr("1.1.1.1"),
		DstPort: 443,
		Family:  2,
		Errno:   0,
	}
	if d.DstIP.String() != "1.1.1.1" {
		t.Fatal()
	}
}

func TestEventComposition(t *testing.T) {
	now := time.Now()
	e := Event{
		ID: 42, Ts: now, Source: SourceEBPF, Type: "EXEC",
		Host: "h1", PID: 100, Comm: "ls",
		Detail: &ExecDetail{Filename: "/bin/ls"},
	}
	d, ok := e.Detail.(*ExecDetail)
	if !ok || d.Filename != "/bin/ls" {
		t.Fatal("type-assert failed")
	}
}
