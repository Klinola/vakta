package auditd

import (
	"context"
	"time"
)

// Group consumes single Records from in, accumulates them by Seq, and emits
// the grouped batch on either an AUDIT_EOE marker (type "EOE") or a fallback
// timeout after the first record of a sequence was seen (default 50 ms).
//
// The output channel closes when in closes (after draining) or when ctx
// is cancelled. EOE records are dropped from the emitted batch.
func Group(ctx context.Context, in <-chan Record) <-chan []Record {
	out := make(chan []Record, 256)
	go groupLoop(ctx, in, out, 50*time.Millisecond)
	return out
}

// pendingGroup buffers records sharing a Seq plus their oldest arrival time.
type pendingGroup struct {
	records []Record
	added   time.Time
}

func groupLoop(ctx context.Context, in <-chan Record, out chan<- []Record, timeout time.Duration) {
	defer close(out)
	pending := map[uint32]*pendingGroup{}
	// Tick at half the timeout so a group hits its deadline within timeout/2.
	tick := time.NewTicker(timeout / 2)
	defer tick.Stop()

	flush := func(seq uint32) {
		g, ok := pending[seq]
		if !ok || len(g.records) == 0 {
			delete(pending, seq)
			return
		}
		batch := g.records
		delete(pending, seq)
		select {
		case out <- batch:
		case <-ctx.Done():
		}
	}

	flushExpired := func() {
		now := time.Now()
		for seq, g := range pending {
			if now.Sub(g.added) >= timeout {
				flush(seq)
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			// drain pending into out before returning, best-effort.
			for seq := range pending {
				flush(seq)
			}
			return
		case <-tick.C:
			flushExpired()
		case rec, ok := <-in:
			if !ok {
				// input closed; flush all and exit
				for seq := range pending {
					flush(seq)
				}
				return
			}
			if rec.Type == "EOE" {
				flush(rec.Seq)
				continue
			}
			g, exists := pending[rec.Seq]
			if !exists {
				g = &pendingGroup{added: time.Now()}
				pending[rec.Seq] = g
			}
			g.records = append(g.records, rec)
		}
	}
}
