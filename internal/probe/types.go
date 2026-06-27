package probe

import "net/netip"

// EventType is the discriminator stamped on every record's header.
// Values mirror enum vakta_event_type in probe.bpf.c.
type EventType uint32

const (
	EventExecAttempt EventType = 1
	EventExec        EventType = 2
	EventConnect     EventType = 3
	EventOpen        EventType = 4
	EventClone       EventType = 5
	EventUnshare     EventType = 6
	EventPtrace      EventType = 7
	EventModuleLoad  EventType = 8
	EventBPFLoad     EventType = 9
	EventMemfd       EventType = 10
	EventChmod       EventType = 11
	EventMmapExec    EventType = 12
	EventProcProbe   EventType = 13
)

// EventHeader is the 44-byte common prefix of every record on the wire.
// Field order and types MUST match struct vakta_hdr in probe.bpf.c.
type EventHeader struct {
	TsNs uint64
	PID  uint32
	PPID uint32
	UID  uint32
	GID  uint32
	Type EventType
	Comm [16]byte
}

// Event is what the probe channel delivers. Consumers type-switch:
//
//	switch ev := ev.(type) {
//	case *probe.ExecEvent:    // ...
//	case *probe.ConnectEvent: // ...
//	}
type Event interface {
	Header() EventHeader
}

type ExecAttemptEvent struct {
	EventHeader
	Filename string
}

func (e *ExecAttemptEvent) Header() EventHeader { return e.EventHeader }

type ExecEvent struct {
	EventHeader
	Argv [][]byte // raw \0-delimited blob split by parser
}

func (e *ExecEvent) Header() EventHeader { return e.EventHeader }

type ConnectEvent struct {
	EventHeader
	Family  uint16
	DstIP   netip.Addr
	DstPort uint16
}

func (e *ConnectEvent) Header() EventHeader { return e.EventHeader }

type OpenEvent struct {
	EventHeader
	Path  string
	Flags int32
}

func (e *OpenEvent) Header() EventHeader { return e.EventHeader }

type CloneEvent struct {
	EventHeader
	CloneFlags uint64
}

func (e *CloneEvent) Header() EventHeader { return e.EventHeader }

type UnshareEvent struct {
	EventHeader
	UnshareFlags uint64
}

func (e *UnshareEvent) Header() EventHeader { return e.EventHeader }

type PtraceEvent struct {
	EventHeader
	Request   int64
	TargetPID uint32
}

func (e *PtraceEvent) Header() EventHeader { return e.EventHeader }

type ModuleLoadEvent struct {
	EventHeader
	Name string
}

func (e *ModuleLoadEvent) Header() EventHeader { return e.EventHeader }

type BPFLoadEvent struct {
	EventHeader
	ProgType uint32
}

func (e *BPFLoadEvent) Header() EventHeader { return e.EventHeader }

type MemfdEvent struct {
	EventHeader
	Name  string
	Flags uint32
}

func (e *MemfdEvent) Header() EventHeader { return e.EventHeader }

type ChmodEvent struct {
	EventHeader
	Path string
	Mode uint32
}

func (e *ChmodEvent) Header() EventHeader { return e.EventHeader }

type MmapExecEvent struct {
	EventHeader
	Addr uint64
	Len  uint64
	Prot uint32
}

func (e *MmapExecEvent) Header() EventHeader { return e.EventHeader }

type ProcProbeEvent struct {
	EventHeader
	TargetPID uint32
}

func (e *ProcProbeEvent) Header() EventHeader { return e.EventHeader }
