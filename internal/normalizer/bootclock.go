package normalizer

import "time"

// bootWall is the wall-clock instant at which CLOCK_MONOTONIC read zero, i.e.
// the reference point every bpf_ktime_get_ns() reading is relative to. Sampled
// once at package init: time.Now() and the monotonic clock are read back to
// back, so their difference is the boot instant to within the cost of one
// syscall. Zero if the monotonic clock is unavailable (non-Linux builds).
var bootWall = sampleBootWall()

func sampleBootWall() time.Time {
	wall := time.Now()
	mono, ok := readMonotonic()
	if !ok {
		return time.Time{}
	}
	return wall.Add(-mono)
}

// monotonicToWall converts a CLOCK_MONOTONIC nanosecond reading — what
// bpf_ktime_get_ns() returns — into wall-clock time.
//
// eBPF events carry monotonic timestamps, which are nanoseconds since boot,
// NOT since the Unix epoch. Passing them straight to time.Unix put every eBPF
// event in January 1970. That was not merely a cosmetic display bug: retention
// pruning deletes rows whose ts is older than the cutoff, so every eBPF event
// was deleted on the next hourly pass and every eBPF-derived alert had its
// event_id NULLed, leaving critical alerts with no evidence behind them. Time
// range queries over eBPF events were silently wrong for the same reason.
//
// The conversion has to happen on the agent, where the monotonic clock belongs
// to the same kernel that stamped the event; forwarded events already carry a
// wall-clock time.Time on the wire.
func monotonicToWall(ns uint64) time.Time {
	if bootWall.IsZero() {
		return time.Now()
	}
	return bootWall.Add(time.Duration(ns))
}
