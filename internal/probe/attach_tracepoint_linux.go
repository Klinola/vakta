//go:build linux

package probe

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// isPermissionDenied detects EACCES / EPERM in error chains, with a string
// fallback for libraries that flatten the chain via fmt.Errorf("%v", err).
// cilium/ebpf v0.22 wraps BPF_LINK_CREATE failures with %v in
// link/perf_event.go:326, which breaks errors.Is — hence the string check.
func isPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "operation not permitted")
}

// attachTracepointLegacy attaches a BPF program to a kernel tracepoint via
// the pre-5.15 perf_event_open + PERF_EVENT_IOC_SET_BPF path. Used as a
// fallback when link.Tracepoint (which prefers BPF_LINK_CREATE) is rejected
// at runtime with EACCES/EPERM — observed on RHEL/Rocky 9.x kernels where
// the bpf LSM is active.
//
// Mirrors what cilium/ebpf's unexported attachPerfEventIoctl does, but is
// callable from outside the link package.
func attachTracepointLegacy(group, name string, prog *ebpf.Program) (io.Closer, error) {
	idPath := fmt.Sprintf("/sys/kernel/debug/tracing/events/%s/%s/id", group, name)
	raw, err := os.ReadFile(idPath)
	if err != nil {
		return nil, fmt.Errorf("read tracepoint id %s: %w", idPath, err)
	}
	tid, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse tracepoint id %q: %w", string(raw), err)
	}

	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
		Config:      uint64(tid),
	}
	// pid=-1, cpu=0, group_fd=-1, flags=CLOEXEC means "all PIDs on CPU 0"
	// which is sufficient for tracepoints (kernel multicasts to all CPUs
	// in the program; the BPF prog runs once per event regardless of cpu).
	fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("perf_event_open: %w", err)
	}

	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, prog.FD()); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("PERF_EVENT_IOC_SET_BPF: %w", err)
	}
	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("PERF_EVENT_IOC_ENABLE: %w", err)
	}
	return &perfEventCloser{fd: fd}, nil
}

// perfEventCloser releases the perf_event fd. PERF_EVENT_IOC_DISABLE is
// implicit on close.
type perfEventCloser struct{ fd int }

func (p *perfEventCloser) Close() error {
	if p.fd < 0 {
		return nil
	}
	err := unix.Close(p.fd)
	p.fd = -1
	return err
}
