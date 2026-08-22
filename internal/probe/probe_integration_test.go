//go:build linux && integration

package probe

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestProbeReceivesExecEvent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (CAP_BPF+CAP_PERFMON or full root)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	m, ch, err := New(ctx)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()

	// Let attach settle before exec.
	time.Sleep(100 * time.Millisecond)

	if err := exec.Command("/bin/true").Run(); err != nil {
		t.Fatalf("/bin/true: %v", err)
	}

	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev := <-ch:
			e, ok := ev.(*ExecEvent)
			if !ok {
				continue
			}
			if len(e.Argv) == 0 {
				continue
			}
			argv0 := string(bytes.TrimRight(e.Argv[0], "\x00"))
			if strings.HasSuffix(argv0, "/true") || argv0 == "true" {
				if e.Ret != 0 {
					t.Fatalf("ExecEvent.Ret = %d, want 0", e.Ret)
				}
				return
			}
		case <-deadline:
			stats := m.Stats()
			t.Fatalf("no EXEC event for /bin/true; stats=%+v", stats)
		}
	}
}

func TestProbeReceivesConnectEventWithErrno(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (CAP_BPF+CAP_PERFMON or full root)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	m, ch, err := New(ctx)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()

	// Let attach settle before connect.
	time.Sleep(100 * time.Millisecond)

	// Trigger a guaranteed-failing connect: TCP 4444 on loopback. Nothing
	// listens there → -ECONNREFUSED (-111). Port 4444 specifically because the
	// kernel now only emits CONNECT for ports a rule names (see
	// connect_port_is_watched in probe.bpf.c); this used to use port 1, which
	// is no longer reported.
	c, _ := net.DialTimeout("tcp", "127.0.0.1:4444", 200*time.Millisecond)
	if c != nil {
		_ = c.Close()
	}

	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev := <-ch:
			e, ok := ev.(*ConnectEvent)
			if !ok {
				continue
			}
			if e.DstPort != 4444 {
				continue
			}
			// Expect negative ret. Common values:
			//   -111 ECONNREFUSED   (port closed)
			//   -115 EINPROGRESS    (non-blocking connect in flight, less likely here)
			if e.Ret >= 0 {
				t.Fatalf("connect to 127.0.0.1:4444 should fail with negative errno, got Ret = %d", e.Ret)
			}
			return
		case <-deadline:
			t.Fatalf("no ConnectEvent to 127.0.0.1:4444 observed; stats=%+v", m.Stats())
		}
	}
}
