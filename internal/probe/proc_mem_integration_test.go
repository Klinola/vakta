//go:build linux && integration

package probe

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestProcMemOpenIsDetected covers the T1055 process-injection probe that
// proc-mem-open.yaml depends on. It reads another process's /proc/<pid>/mem and
// expects a PROC_MEM_OPEN event.
//
// This failed before the accompanying fix: parse_proc_mem_pid() compared the
// suffix against "/men", so no real path ever matched and the event type — and
// both rules built on it — had never fired.
func TestProcMemOpenIsDetected(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (CAP_BPF+CAP_PERFMON or full root)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	m, ch, err := New(ctx)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()

	time.Sleep(300 * time.Millisecond) // let attach settle

	// PID 1 is always another process. The open is what the probe hooks; the
	// read is irrelevant and would fail anyway, so ignore the outcome.
	if f, err := os.Open("/proc/1/mem"); err == nil {
		_ = f.Close()
	} else {
		t.Logf("open /proc/1/mem returned %v (the openat still reaches the probe)", err)
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-ch:
			e, ok := ev.(*ProcMemOpenEvent)
			if !ok {
				continue
			}
			if e.TargetPID != 1 {
				continue
			}
			return
		case <-deadline:
			t.Fatalf("no PROC_MEM_OPEN event for /proc/1/mem within 5s; stats=%+v", m.Stats())
		}
	}
}
