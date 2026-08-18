package engine

import (
	"testing"
	"time"

	"github.com/Klinola/vakta/internal/normalizer"
)

// TestBuiltinKcoreRule exercises the shipped open-proc-kcore rule against the
// events that actually occur on a Kubernetes node. The false positive it pins
// is a real one: a containerised util-linux lscpu falls back to scanning
// /dev/mem for the SMBIOS table because /sys/firmware/dmi is absent inside a
// container, the open fails with ENOENT because containers have no /dev/mem,
// and the rule paged someone at P0 for it.
func TestBuiltinKcoreRule(t *testing.T) {
	e, err := New(nil) // built-in rules only
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	openEvent := func(comm, path string, ret int64) normalizer.Event {
		return normalizer.Event{
			Ts: time.Now(), Source: normalizer.SourceEBPF, Type: "OPEN",
			Comm: comm, Ret: ret, Detail: &normalizer.OpenDetail{Path: path},
		}
	}

	cases := []struct {
		name string
		ev   normalizer.Event
		want bool
	}{
		{"containerised lscpu refused /dev/mem", openEvent("lscpu", "/dev/mem", -2), false},
		{"refused /proc/kcore", openEvent("evil", "/proc/kcore", -13), false},
		{"successful /proc/kcore read", openEvent("evil", "/proc/kcore", 3), true},
		{"successful /dev/mem read", openEvent("evil", "/dev/mem", 7), true},
		{"successful /dev/kmem read", openEvent("evil", "/dev/kmem", 7), true},
		{"successful /proc/kmem read", openEvent("evil", "/proc/kmem", 7), true},
		{"runc masking kcore", openEvent("runc", "/proc/kcore", 5), false},
		{"runc init masking kcore", openEvent("runc:[2:INIT]", "/proc/kcore", 5), false},
		{"comm merely starting with runc", openEvent("runcrypter", "/proc/kcore", 5), true},
		{"unrelated path", openEvent("evil", "/etc/hosts", 3), false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := false
			for _, m := range e.Evaluate(c.ev) {
				if m.Rule.ID == "open-proc-kcore" {
					got = true
				}
			}
			if got != c.want {
				t.Fatalf("open-proc-kcore fired=%v, want %v", got, c.want)
			}
		})
	}
}

// TestBuiltinShadowRuleStillCatchesDeniedReads guards the deliberate asymmetry:
// unlike open-proc-kcore, a refused read of /etc/shadow is the signal, not
// noise, so that rule must keep firing when the syscall fails.
func TestBuiltinShadowRuleStillCatchesDeniedReads(t *testing.T) {
	e, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ev := normalizer.Event{
		Ts: time.Now(), Source: normalizer.SourceEBPF, Type: "OPEN",
		Comm: "cat", UID: 1000, Ret: -13,
		Detail: &normalizer.OpenDetail{Path: "/etc/shadow"},
	}
	for _, m := range e.Evaluate(ev) {
		if m.Rule.ID == "open-shadow-file" {
			return
		}
	}
	t.Fatal("open-shadow-file did not fire on a denied read")
}
