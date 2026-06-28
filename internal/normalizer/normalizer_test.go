package normalizer

import (
	"testing"
	"time"

	"github.com/Klinola/vakta/internal/probe"
)

func TestNormalizerFansInProbeOnly(t *testing.T) {
	src := make(chan probe.Event, 4)
	n := New(src, nil, nil, "h1")
	defer n.Close()
	src <- &probe.ExecEvent{
		EventHeader: probe.EventHeader{TsNs: 1, PID: 7, Type: probe.EventExec},
		Argv:        [][]byte{[]byte("/bin/true")},
	}
	close(src)

	select {
	case ev := <-n.Events():
		if ev.Type != "EXEC" || ev.ID == 0 {
			t.Fatalf("ev=%+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no event")
	}
}

func TestNormalizerAssignsMonotonicID(t *testing.T) {
	src := make(chan probe.Event, 4)
	n := New(src, nil, nil, "h1")
	defer n.Close()
	for i := 0; i < 3; i++ {
		src <- &probe.ExecEvent{
			EventHeader: probe.EventHeader{TsNs: uint64(i + 1), PID: 1, Type: probe.EventExec},
		}
	}
	close(src)

	var ids []uint64
	deadline := time.After(time.Second)
	for len(ids) < 3 {
		select {
		case ev := <-n.Events():
			ids = append(ids, ev.ID)
		case <-deadline:
			t.Fatalf("got only %d events", len(ids))
		}
	}
	if ids[0] >= ids[1] || ids[1] >= ids[2] {
		t.Fatalf("ids not monotonic: %v", ids)
	}
}
