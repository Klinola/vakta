package normalizer

import (
	"net/netip"
	"testing"

	"github.com/vakta-project/vakta/internal/probe"
)

func TestFromProbeExec(t *testing.T) {
	src := &probe.ExecEvent{
		EventHeader: probe.EventHeader{
			TsNs: 1, CgroupID: 99, PID: 100, PPID: 1, UID: 1000, GID: 1000,
			Type: probe.EventExec,
			Comm: [16]byte{'l', 's', 0},
		},
		Ret:  0,
		Argv: [][]byte{[]byte("ls"), []byte("-la"), []byte("/tmp")},
	}
	ev := FromProbe(src, "host-1")
	if ev.Type != "EXEC" || ev.Host != "host-1" || ev.PID != 100 || ev.CgroupID != 99 {
		t.Fatalf("ev=%+v", ev)
	}
	d, ok := ev.Detail.(*ExecDetail)
	if !ok || len(d.Argv) != 3 || d.Argv[0] != "ls" {
		t.Fatalf("detail=%+v ok=%v", ev.Detail, ok)
	}
}

func TestFromProbeConnect(t *testing.T) {
	src := &probe.ConnectEvent{
		EventHeader: probe.EventHeader{TsNs: 1, PID: 200, Type: probe.EventConnect},
		Ret:         -111,
		Family:      2,
		DstIP:       netip.MustParseAddr("1.1.1.1"),
		DstPort:     443,
	}
	ev := FromProbe(src, "h")
	if ev.Type != "CONNECT" {
		t.Fatalf("type=%s", ev.Type)
	}
	d := ev.Detail.(*ConnectDetail)
	if d.DstPort != 443 || d.Errno != -111 {
		t.Fatalf("d=%+v", d)
	}
}

func TestFromProbeChmodSUIDFlag(t *testing.T) {
	src := &probe.ChmodEvent{
		EventHeader: probe.EventHeader{TsNs: 1, PID: 300, Type: probe.EventChmod},
		Mode:        0o4755, // SUID set
		Path:        "/tmp/x",
	}
	ev := FromProbe(src, "h")
	d := ev.Detail.(*ChmodDetail)
	if !d.SUID {
		t.Fatal("SUID flag not set for mode 0o4755")
	}
	if d.SGID {
		t.Fatal("SGID flag erroneously set")
	}
}
