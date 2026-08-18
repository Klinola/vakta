package normalizer

import (
	"testing"
	"time"

	"github.com/Klinola/vakta/internal/probe"
)

func TestMonotonicToWallReturnsWallClock(t *testing.T) {
	mono, ok := readMonotonic()
	if !ok {
		t.Skip("no monotonic clock on this platform")
	}
	got := monotonicToWall(uint64(mono))
	if d := time.Since(got); d < -time.Second || d > time.Second {
		t.Fatalf("converting the current monotonic reading gave %s, %s away from now", got, d)
	}
}

func TestMonotonicToWallPreservesDeltas(t *testing.T) {
	const base = 1_000_000_000
	const delta = 250 * time.Millisecond
	a := monotonicToWall(base)
	b := monotonicToWall(base + uint64(delta))
	if got := b.Sub(a); got != delta {
		t.Fatalf("delta = %s, want %s", got, delta)
	}
}

// TestFromProbeTimestampIsNotEpoch guards the regression that made every eBPF
// event land in January 1970: bpf_ktime_get_ns() is nanoseconds since boot, so
// feeding it to time.Unix produced a date old enough for retention pruning to
// delete the row on its next pass.
func TestFromProbeTimestampIsNotEpoch(t *testing.T) {
	mono, ok := readMonotonic()
	if !ok {
		t.Skip("no monotonic clock on this platform")
	}
	src := &probe.OpenEvent{
		EventHeader: probe.EventHeader{TsNs: uint64(mono), PID: 1, Type: probe.EventOpen},
		Path:        "/proc/kcore",
	}
	ev := FromProbe(src, "h")
	if d := time.Since(ev.Ts); d < -time.Minute || d > time.Minute {
		t.Fatalf("eBPF event timestamp %s is %s away from now", ev.Ts, d)
	}
}
