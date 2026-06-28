//go:build linux

package probe

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIsPermissionDenied(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"wrapped EACCES", fmt.Errorf("foo: %w", unix.EACCES), true},
		{"wrapped EPERM", fmt.Errorf("foo: %w", unix.EPERM), true},
		// cilium/ebpf v0.22 link/perf_event.go:326 flattens the chain with %v.
		{"flattened permission denied", fmt.Errorf("cannot create bpf perf link: %v", unix.EACCES), true},
		{"flattened operation not permitted", fmt.Errorf("foo: %v", unix.EPERM), true},
		{"unrelated", errors.New("connection refused"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isPermissionDenied(c.err); got != c.want {
				t.Errorf("isPermissionDenied(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}
