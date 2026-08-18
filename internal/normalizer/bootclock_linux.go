//go:build linux

package normalizer

import (
	"time"

	"golang.org/x/sys/unix"
)

// readMonotonic returns the current CLOCK_MONOTONIC reading — the same clock
// bpf_ktime_get_ns() samples in the BPF programs. Both exclude time spent
// suspended, so the two stay in step.
func readMonotonic() (time.Duration, bool) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, false
	}
	return time.Duration(ts.Nano()), true
}
