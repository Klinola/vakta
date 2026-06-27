package probe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Stats is a snapshot of probe runtime metrics. Returned by Manager.Stats().
type Stats struct {
	Dropped            uint64
	DeliveredByType    map[EventType]uint64
	MissingTracepoints []string
}

// attachSpec is the (tracepoint group, name, program) tuple used to drive attachment.
type attachSpec struct {
	group, name string
	prog        *ebpf.Program
}

// Manager owns the loaded BPF objects, the attached links, and the ringbuf reader.
type Manager struct {
	objs   probeObjects
	links  []link.Link
	reader *ringbuf.Reader

	out  chan Event
	done chan struct{}

	statsMu              sync.Mutex
	statsMissing         []string
	statsDeliveredByType map[EventType]uint64
	statsDropped         atomic.Uint64

	closeOnce sync.Once
	closeErr  error
}

// New loads the BPF object, attaches every available tracepoint, and starts the
// ringbuf reader. The returned channel yields typed Events until ctx is canceled
// or Close is called. Failures to attach individual tracepoints are surfaced
// via Stats().MissingTracepoints rather than fatal errors.
func New(ctx context.Context) (*Manager, <-chan Event, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("remove memlock: %w", err)
	}

	m := &Manager{
		out:                  make(chan Event, 4096),
		done:                 make(chan struct{}),
		statsDeliveredByType: make(map[EventType]uint64),
	}

	if err := loadProbeObjects(&m.objs, nil); err != nil {
		return nil, nil, fmt.Errorf("load BPF object: %w", err)
	}

	specs := m.attachSpecs()
	for _, s := range specs {
		l, err := link.Tracepoint(s.group, s.name, s.prog, nil)
		if err != nil {
			slog.Warn("probe: tracepoint attach failed",
				"group", s.group, "name", s.name, "err", err)
			m.statsMissing = append(m.statsMissing, s.group+"/"+s.name)
			continue
		}
		m.links = append(m.links, l)
	}

	if len(m.links) == 0 {
		_ = m.objs.Close()
		return nil, nil, errors.New("no tracepoints attached")
	}

	rd, err := ringbuf.NewReader(m.objs.Events)
	if err != nil {
		m.closeLinks()
		_ = m.objs.Close()
		return nil, nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	m.reader = rd

	go m.readLoop()
	go m.watchCtx(ctx)

	return m, m.out, nil
}

func (m *Manager) attachSpecs() []attachSpec {
	// Filled out as more SEC programs come online in Task 7.
	// Each generated probeObjects field name comes from the SEC handler's C function name
	// (CamelCase). Verify exact names by reading probe_bpfel.go.
	return []attachSpec{
		{"sched", "sched_process_exec", m.objs.HandleSchedExec},
		{"syscalls", "sys_enter_execve", m.objs.HandleSysEnterExecve},
		{"syscalls", "sys_enter_execveat", m.objs.HandleSysEnterExecveat},
		{"syscalls", "sys_enter_connect", m.objs.HandleSysEnterConnect},
		{"syscalls", "sys_enter_openat", m.objs.HandleSysEnterOpenat},
		{"syscalls", "sys_enter_open", m.objs.HandleSysEnterOpen},
		{"syscalls", "sys_enter_clone", m.objs.HandleSysEnterClone},
		{"syscalls", "sys_enter_clone3", m.objs.HandleSysEnterClone3},
		{"syscalls", "sys_enter_unshare", m.objs.HandleSysEnterUnshare},
		{"syscalls", "sys_enter_ptrace", m.objs.HandleSysEnterPtrace},
	}
}

func (m *Manager) readLoop() {
	defer close(m.done)
	for {
		rec, err := m.reader.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			return
		}
		if err != nil {
			slog.Warn("probe: ringbuf read error", "err", err)
			continue
		}
		ev, perr := parseRecord(rec.RawSample)
		if perr != nil {
			slog.Warn("probe: parseRecord", "err", perr, "bytes", len(rec.RawSample))
			continue
		}
		m.statsMu.Lock()
		m.statsDeliveredByType[ev.Header().Type]++
		m.statsMu.Unlock()
		m.out <- ev // blocks if consumer is slow → backpressure to kernel
	}
}

func (m *Manager) watchCtx(ctx context.Context) {
	<-ctx.Done()
	_ = m.Close()
}

// Stats returns a snapshot of runtime counters.
func (m *Manager) Stats() Stats {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	deliveredCopy := make(map[EventType]uint64, len(m.statsDeliveredByType))
	for k, v := range m.statsDeliveredByType {
		deliveredCopy[k] = v
	}
	missingCopy := make([]string, len(m.statsMissing))
	copy(missingCopy, m.statsMissing)
	return Stats{
		Dropped:            m.statsDropped.Load(),
		DeliveredByType:    deliveredCopy,
		MissingTracepoints: missingCopy,
	}
}

// Close detaches all links, closes the BPF object, and stops the reader.
// Safe to call multiple times.
func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		if m.reader != nil {
			_ = m.reader.Close()
		}
		<-m.done // wait for readLoop to exit
		m.closeLinks()
		m.closeErr = m.objs.Close()
		close(m.out)
	})
	return m.closeErr
}

func (m *Manager) closeLinks() {
	for i := len(m.links) - 1; i >= 0; i-- {
		_ = m.links[i].Close()
	}
}
