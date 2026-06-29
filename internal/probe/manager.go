package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

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

type attachKind int

const (
	attachTracepoint attachKind = iota
	attachKprobe
	attachRawTracepoint
)

// attachSpec describes one BPF program attachment. For tracepoint, group+name
// identify the kernel tracepoint. For kprobe, name is the kernel symbol and
// group is ignored.
type attachSpec struct {
	kind        attachKind
	group, name string
	prog        *ebpf.Program
}

// Manager owns the loaded BPF objects, the attached links, and the ringbuf reader.
type Manager struct {
	objs           probeObjects
	links          []link.Link
	legacyClosers  []io.Closer // legacy perf_event fds for kernels that reject BPF_LINK_CREATE
	reader         *ringbuf.Reader

	out  chan Event
	done chan struct{}
	quit chan struct{} // closed by Close to release a stuck send

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
	if err := ensureBPFFS(); err != nil {
		// Non-fatal: most BPF objects don't require pinning. Log so misconfigured
		// hosts are diagnosable; pinning failures will surface later if used.
		slog.Warn("probe: bpffs not mountable, continuing without pinning support", "err", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("remove memlock: %w", err)
	}

	m := &Manager{
		out:                  make(chan Event, 4096),
		done:                 make(chan struct{}),
		quit:                 make(chan struct{}),
		statsDeliveredByType: make(map[EventType]uint64),
	}

	if err := loadProbeObjects(&m.objs, nil); err != nil {
		return nil, nil, fmt.Errorf("load BPF object: %w", err)
	}

	specs := m.attachSpecs()
	permDeniedCount := 0
	for _, s := range specs {
		var l link.Link
		var err error
		switch s.kind {
		case attachTracepoint:
			l, err = link.Tracepoint(s.group, s.name, s.prog, nil)
			if err != nil && isPermissionDenied(err) {
				// Runtime fallback for kernels (e.g. RHEL/Rocky 9 with active
				// bpf LSM) where the cilium/ebpf feature probe reports
				// BPF_LINK_CREATE as supported but actual attach is rejected.
				slog.Debug("probe: link API denied, falling back to legacy perf_event_open",
					"tp", s.group+"/"+s.name, "err", err)
				if closer, lerr := attachTracepointLegacy(s.group, s.name, s.prog); lerr == nil {
					m.legacyClosers = append(m.legacyClosers, closer)
					err = nil
				} else {
					err = fmt.Errorf("link.Tracepoint: %w; legacy fallback: %v", err, lerr)
				}
			}
		case attachKprobe:
			l, err = link.Kprobe(s.name, s.prog, nil)
		case attachRawTracepoint:
			// tp_btf attaches via LinkCreateTracing/RawTracepointOpen — bypasses
			// perf_event_set_bpf_prog (the path that returns EACCES on Rocky 9).
			// SEC("tp_btf/<name>") carries the attach target in BTF, so opts.Name
			// is unused and s.name is informational only.
			l, err = link.AttachTracing(link.TracingOptions{Program: s.prog})
		}
		if err != nil {
			// Suppress per-tracepoint WARN when the failure is a kernel-level
			// permission deny — emit a single summary after the loop instead.
			// Other failures (missing tracepoint, kprobe inline, etc.) still WARN.
			if isPermissionDenied(err) {
				permDeniedCount++
				slog.Debug("probe: attach denied by kernel",
					"kind", s.kind, "group", s.group, "name", s.name, "err", err)
			} else {
				slog.Warn("probe: attach failed",
					"kind", s.kind, "group", s.group, "name", s.name, "err", err)
			}
			m.statsMissing = append(m.statsMissing, s.group+"/"+s.name)
			continue
		}
		if l != nil {
			m.links = append(m.links, l)
		}
	}

	// Single-line summary so audit/Rocky LSM nodes don't spam logs at startup.
	if permDeniedCount > 0 {
		slog.Warn("probe: kernel denied BPF attach on N probes — degraded mode",
			"denied", permDeniedCount, "succeeded", len(m.links)+len(m.legacyClosers),
			"hint", "Rocky/RHEL with bpf LSM active blocks tracepoint attach; agent will run with auditd + k8s_audit only on this node")
	}

	if len(m.links) == 0 && len(m.legacyClosers) == 0 {
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
	go func() {
		t := time.NewTicker(1 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				m.refreshDrops()
			case <-m.done:
				return
			}
		}
	}()

	return m, m.out, nil
}

func (m *Manager) refreshDrops() {
	var perCPU []uint64
	zero := uint32(0)
	if err := m.objs.Drops.Lookup(&zero, &perCPU); err != nil {
		slog.Warn("probe: drops map lookup", "err", err)
		return
	}
	var sum uint64
	for _, v := range perCPU {
		sum += v
	}
	m.statsDropped.Store(sum)
}

func (m *Manager) attachSpecs() []attachSpec {
	// Each generated probeObjects field name comes from the SEC handler's C function name
	// (CamelCase). Verify exact names by reading probe_bpfel.go.
	return []attachSpec{
		{attachTracepoint, "sched", "sched_process_exec", m.objs.HandleSchedExec},
		{attachKprobe, "", "do_init_module", m.objs.HandleDoInitModule},
		// tp_btf dispatchers (issue #1): bypass perf_event_set_bpf_prog (EACCES on Rocky/RHEL 9.x).
		// group="" because raw_tp attach takes only a tracepoint name.
		{attachRawTracepoint, "", "sys_enter", m.objs.HandleRawSysEnter},
		{attachRawTracepoint, "", "sys_exit", m.objs.HandleRawSysExit},
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
		select {
		case m.out <- ev:
			// backpressure to kernel; consumer is draining
		case <-m.quit:
			return
		}
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
		close(m.quit) // release any goroutine stuck on m.out <- ev
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
	for i := len(m.legacyClosers) - 1; i >= 0; i-- {
		_ = m.legacyClosers[i].Close()
	}
}
