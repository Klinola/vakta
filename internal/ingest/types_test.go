package ingest

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/Klinola/vakta/internal/normalizer"
)

func TestRoundTripAllDetailTypes(t *testing.T) {
	base := normalizer.Event{
		ID:       42,
		Ts:       time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC),
		Source:   normalizer.SourceEBPF,
		Type:     "test",
		Host:     "node-1",
		CgroupID: 1234,
		PID:      111,
		PPID:     1,
		UID:      1000,
		GID:      1000,
		Comm:     "bash",
		Ret:      0,
	}

	cases := []struct {
		name   string
		detail any
	}{
		{"nil", nil},
		{"exec", &normalizer.ExecDetail{Filename: "/bin/sh", Argv: []string{"sh", "-c", "echo hi"}}},
		{"connect", &normalizer.ConnectDetail{DstIP: netip.MustParseAddr("10.0.0.1"), DstPort: 443, Family: 2, Errno: 0}},
		{"open", &normalizer.OpenDetail{Path: "/etc/passwd", Flags: 0}},
		{"clone", &normalizer.CloneDetail{CloneFlags: 0x1234}},
		{"unshare", &normalizer.UnshareDetail{UnshareFlags: 0x5678}},
		{"ptrace", &normalizer.PtraceDetail{Request: 16, TargetPID: 222}},
		{"module", &normalizer.ModuleDetail{Name: "evil_mod"}},
		{"bpf", &normalizer.BPFLoadDetail{ProgType: 5}},
		{"memfd", &normalizer.MemfdDetail{Name: "anon", Flags: 1}},
		{"chmod", &normalizer.ChmodDetail{Path: "/tmp/x", Mode: 0o4755, SUID: true, SGID: false}},
		{"mmap", &normalizer.MmapExecDetail{Addr: 0xdeadbeef, Len: 4096, Prot: 7}},
		{"procprobe", &normalizer.ProcProbeDetail{TargetPID: 333}},
		{"auditfim", &normalizer.AuditFIMDetail{Path: "/etc/shadow", AuditKey: "fim_shadow", Op: "write"}},
		{"k8s", &normalizer.K8sDetail{Verb: "create", Resource: "pods", Namespace: "default", Name: "x", Username: "u", SourceIP: "1.2.3.4"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := base
			ev.Detail = tc.detail
			wire := ToWire(ev)
			got, err := FromWire(wire)
			if err != nil {
				t.Fatalf("FromWire: %v", err)
			}
			if got.ID != ev.ID || got.Type != ev.Type || got.Host != ev.Host {
				t.Fatalf("scalar mismatch: got=%+v want=%+v", got, ev)
			}
			if !got.Ts.Equal(ev.Ts) {
				t.Fatalf("Ts mismatch: got=%v want=%v", got.Ts, ev.Ts)
			}
			if !reflect.DeepEqual(got.Detail, ev.Detail) {
				t.Fatalf("Detail mismatch: got=%#v want=%#v", got.Detail, ev.Detail)
			}
		})
	}
}

func TestFromWireUnknownDetailType(t *testing.T) {
	_, err := FromWire(WireEvent{DetailType: "made-up"})
	if err == nil {
		t.Fatal("expected error for unknown detail_type")
	}
}
