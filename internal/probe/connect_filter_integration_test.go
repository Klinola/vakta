//go:build linux && integration

package probe

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

// TestConnectFilterKeepsWatchedPortsDropsNoise is the CONNECT half of the
// allowlist contract added after the 2026-08-18→22 incident. Once OPEN was
// filtered, CONNECT became 95.6% of everything stored — 78% of that port 53,
// the rest Redis, gRPC and Mongo, none of it matched by any rule.
//
// Port 4444 stands in for the watched set (connect-to-known-c2-port); port 53
// stands in for the noise. Nothing needs to be listening on either: the probe
// pairs sys_enter with sys_exit, so a refused connect still reports.
func TestConnectFilterKeepsWatchedPortsDropsNoise(t *testing.T) {
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

	dial := func(addr string) {
		c, _ := net.DialTimeout("tcp", addr, 150*time.Millisecond)
		if c != nil {
			_ = c.Close()
		}
	}

	for i := 0; i < 50; i++ {
		dial("127.0.0.1:53") // noise: the single biggest source in production
	}
	dial("127.0.0.1:4444") // positive control

	var (
		sawWatched bool
		noise      []uint16
		deadline   = time.After(5 * time.Second)
	)
	for !sawWatched {
		select {
		case ev := <-ch:
			e, ok := ev.(*ConnectEvent)
			if !ok {
				continue
			}
			switch e.DstPort {
			case 4444:
				sawWatched = true
			case 53:
				noise = append(noise, e.DstPort)
			}
		case <-deadline:
			t.Fatalf("no CONNECT event for port 4444 within 5s — the filter is dropping a port connect-to-known-c2-port matches; stats=%+v", m.Stats())
		}
	}

	if len(noise) > 0 {
		t.Errorf("kernel emitted %d CONNECT events for port 53; connect_port_is_watched should have dropped every one", len(noise))
	}
}
