package probe

import (
	"testing"
)

func TestEventTypeConstants(t *testing.T) {
	if EventExecAttempt != 1 {
		t.Fatalf("EventExecAttempt = %d, want 1", EventExecAttempt)
	}
	if EventProcProbe != 13 {
		t.Fatalf("EventProcProbe = %d, want 13", EventProcProbe)
	}
}
