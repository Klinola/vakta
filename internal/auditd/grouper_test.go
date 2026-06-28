package auditd

import (
	"context"
	"testing"
	"time"
)

func TestGroupFlushesOnEOE(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := make(chan Record, 4)
	out := Group(ctx, in)
	in <- Record{Seq: 1, Type: "SYSCALL", Fields: map[string]string{"pid": "100"}}
	in <- Record{Seq: 1, Type: "PATH", Fields: map[string]string{"name": "/etc/passwd"}}
	in <- Record{Seq: 1, Type: "EOE"}

	select {
	case batch := <-out:
		if len(batch) != 2 {
			t.Fatalf("expected 2 records (EOE dropped), got %d", len(batch))
		}
		if batch[0].Type != "SYSCALL" || batch[1].Type != "PATH" {
			t.Fatalf("order wrong: %+v", batch)
		}
	case <-time.After(time.Second):
		t.Fatal("no batch received")
	}
}

func TestGroupFlushesOnTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := make(chan Record, 4)
	out := Group(ctx, in)
	in <- Record{Seq: 7, Type: "SYSCALL", Fields: map[string]string{"pid": "1"}}
	// no EOE; should flush via timeout (~50ms)
	select {
	case batch := <-out:
		if len(batch) != 1 {
			t.Fatalf("expected 1 record, got %d", len(batch))
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout flush didn't fire")
	}
}

func TestGroupKeepsSequencesIndependent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := make(chan Record, 8)
	out := Group(ctx, in)
	in <- Record{Seq: 1, Type: "SYSCALL"}
	in <- Record{Seq: 2, Type: "SYSCALL"}
	in <- Record{Seq: 1, Type: "EOE"}
	in <- Record{Seq: 2, Type: "EOE"}

	got := map[uint32]int{}
	for i := 0; i < 2; i++ {
		select {
		case batch := <-out:
			got[batch[0].Seq] = len(batch)
		case <-time.After(time.Second):
			t.Fatalf("only got %d batches", i)
		}
	}
	if got[1] != 1 || got[2] != 1 {
		t.Fatalf("group counts wrong: %+v", got)
	}
}

func TestGroupClosesOutWhenInClosesAndDrains(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := make(chan Record, 4)
	out := Group(ctx, in)
	in <- Record{Seq: 9, Type: "SYSCALL"}
	close(in)
	// expect one batch (drained), then channel closes
	first, ok := <-out
	if !ok || len(first) != 1 {
		t.Fatalf("expected drained batch, ok=%v len=%d", ok, len(first))
	}
	if _, ok := <-out; ok {
		t.Fatal("expected out channel to close after drain")
	}
}
