package normalizer

import (
	"sync"
	"sync/atomic"

	"github.com/Klinola/vakta/internal/probe"
)

const outBufferSize = 8192

// Normalizer fans three input streams into one Event channel.
type Normalizer struct {
	out       chan Event
	nextID    atomic.Uint64
	host      string
	counts    [numSources]atomic.Uint64
	wg        sync.WaitGroup
	closeOnce sync.Once
	done      chan struct{}
}

// numSources bounds the per-source counter array; Source values are small
// consecutive constants starting at 1.
const numSources = int(SourceK8sAudit) + 1

// New starts goroutines for each non-nil input channel. Any of ebpfCh /
// auditCh / k8sCh may be nil to disable that source.
func New(
	ebpfCh <-chan probe.Event,
	auditCh <-chan []AuditdRecord,
	k8sCh <-chan K8sEntry,
	host string,
) *Normalizer {
	n := &Normalizer{
		out:  make(chan Event, outBufferSize),
		host: host,
		done: make(chan struct{}),
	}
	if ebpfCh != nil {
		n.wg.Add(1)
		go n.runProbe(ebpfCh)
	}
	if auditCh != nil {
		n.wg.Add(1)
		go n.runAuditd(auditCh)
	}
	if k8sCh != nil {
		n.wg.Add(1)
		go n.runK8s(k8sCh)
	}
	go func() {
		n.wg.Wait()
		close(n.out)
	}()
	return n
}

// Events returns the unified Event channel. Closes when all input streams close.
func (n *Normalizer) Events() <-chan Event { return n.out }

// Close signals all goroutines to stop draining their input channels.
// Producers should also close their channels; Close is for early abort.
func (n *Normalizer) Close() {
	n.closeOnce.Do(func() { close(n.done) })
}

func (n *Normalizer) emit(ev Event) {
	ev.ID = n.nextID.Add(1)
	if int(ev.Source) < numSources {
		n.counts[ev.Source].Add(1)
	}
	select {
	case n.out <- ev:
	case <-n.done:
	}
}

// Counts reports how many events each source has produced so far. A source
// that is enabled but stays at zero is indistinguishable from a quiet one at a
// glance, which is how two sources went unnoticed while producing nothing at
// all: the auditd netlink socket opens fine but stays silent unless the kernel
// has audit rules loaded, and the k8s audit tailer waits forever for a log file
// that only exists on control-plane nodes.
func (n *Normalizer) Counts() map[Source]uint64 {
	out := make(map[Source]uint64, numSources-1)
	for s := SourceEBPF; int(s) < numSources; s++ {
		out[s] = n.counts[s].Load()
	}
	return out
}

func (n *Normalizer) runProbe(ch <-chan probe.Event) {
	defer n.wg.Done()
	for {
		select {
		case <-n.done:
			return
		case p, ok := <-ch:
			if !ok {
				return
			}
			n.emit(FromProbe(p, n.host))
		}
	}
}

func (n *Normalizer) runAuditd(ch <-chan []AuditdRecord) {
	defer n.wg.Done()
	for {
		select {
		case <-n.done:
			return
		case recs, ok := <-ch:
			if !ok {
				return
			}
			n.emit(FromAuditd(recs, n.host))
		}
	}
}

func (n *Normalizer) runK8s(ch <-chan K8sEntry) {
	defer n.wg.Done()
	for {
		select {
		case <-n.done:
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			n.emit(FromK8s(e, n.host))
		}
	}
}
