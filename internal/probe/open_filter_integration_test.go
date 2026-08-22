//go:build linux && integration

package probe

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestOpenFilterKeepsSensitiveDropsNoise pins the contract added after the
// 2026-08-18→22 incident, where emitting an OPEN for every open()/openat()
// filled a production node's root disk: the kernel must still deliver the
// paths the OPEN rules match, and must deliver nothing for the /proc and /sys
// polling that made up ~99.8% of the old volume.
//
// Both halves matter. "No events" would also pass a drop-everything bug, so
// the sensitive half is the positive control.
func TestOpenFilterKeepsSensitiveDropsNoise(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (CAP_BPF+CAP_PERFMON or full root)")
	}

	// A path that matches the ssh-private-key rule's ".*/id_rsa$" suffix.
	// Using a temp dir keeps the test from touching a real key.
	keyPath := filepath.Join(t.TempDir(), "id_rsa")
	if err := os.WriteFile(keyPath, []byte("not a real key\n"), 0o600); err != nil {
		t.Fatalf("seed key file: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	m, ch, err := New(ctx)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close()

	time.Sleep(300 * time.Millisecond) // let attach settle

	// Noise: exactly the shape that flooded the hub (kubelet/containerd/
	// irqbalance polling procfs). 200 opens is far more than enough — the old
	// build emitted one event per call.
	for i := 0; i < 200; i++ {
		f, err := os.Open("/proc/self/stat")
		if err != nil {
			t.Fatalf("open /proc/self/stat: %v", err)
		}
		_ = f.Close()
	}

	// Positive control: must survive the filter.
	f, err := os.Open(keyPath)
	if err != nil {
		t.Fatalf("open %s: %v", keyPath, err)
	}
	_ = f.Close()

	var (
		sawKey   bool
		noise    []string
		deadline = time.After(5 * time.Second)
	)
	for !sawKey {
		select {
		case ev := <-ch:
			e, ok := ev.(*OpenEvent)
			if !ok {
				continue
			}
			p := strings.TrimRight(e.Path, "\x00")
			switch {
			case p == keyPath:
				sawKey = true
			case strings.HasPrefix(p, "/proc/") || strings.HasPrefix(p, "/sys/"):
				noise = append(noise, p)
			}
		case <-deadline:
			t.Fatalf("no OPEN event for %s within 5s — the filter is dropping a path the ssh-key rule matches; stats=%+v",
				keyPath, m.Stats())
		}
	}

	if len(noise) > 0 {
		show := noise
		if len(show) > 10 {
			show = show[:10]
		}
		t.Errorf("kernel emitted %d /proc or /sys OPEN events; the allowlist should have dropped every one. first few: %v",
			len(noise), show)
	}
}
