//go:build !linux

package normalizer

import "time"

// readMonotonic has no portable implementation off Linux. Callers fall back to
// time.Now() for eBPF event timestamps, which is harmless because the eBPF
// source only runs on Linux in the first place.
func readMonotonic() (time.Duration, bool) { return 0, false }
