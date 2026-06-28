package probe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
)

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
	EventProcMemOpen EventType = 14
)

// EventHeader is the 56-byte common prefix of every record on the wire
// (52 bytes of declared fields + 4 bytes trailing pad to 8-byte alignment).
// CgroupID is the cgroup v2 ID from bpf_get_current_cgroup_id(); 0 if the
// task is in the root cgroup or the kernel lacks cgroup v2.
type EventHeader struct {
	TsNs     uint64
	CgroupID uint64
	PID      uint32
	PPID     uint32
	UID      uint32
	GID      uint32
	Type     EventType
	Comm     [16]byte
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

// Every per-type event carries Ret immediately after EventHeader.
// Ret is the syscall return value captured by the matching sys_exit
// handler: 0 (or fd) on success, negative errno on failure. For
// single-hook events (EXEC, MODULE_LOAD) Ret is always 0.

type ExecAttemptEvent struct {
	EventHeader
	Ret      int64
	Filename string
}

func (e *ExecAttemptEvent) Header() EventHeader { return e.EventHeader }

type ExecEvent struct {
	EventHeader
	Ret  int64
	Argv [][]byte // raw \0-delimited blob split by parser
}

func (e *ExecEvent) Header() EventHeader { return e.EventHeader }

type ConnectEvent struct {
	EventHeader
	Ret     int64
	Family  uint16
	DstIP   netip.Addr
	DstPort uint16
}

func (e *ConnectEvent) Header() EventHeader { return e.EventHeader }

type OpenEvent struct {
	EventHeader
	Ret   int64
	Path  string
	Flags int32
}

func (e *OpenEvent) Header() EventHeader { return e.EventHeader }

type CloneEvent struct {
	EventHeader
	Ret        int64
	CloneFlags uint64
}

func (e *CloneEvent) Header() EventHeader { return e.EventHeader }

type UnshareEvent struct {
	EventHeader
	Ret          int64
	UnshareFlags uint64
}

func (e *UnshareEvent) Header() EventHeader { return e.EventHeader }

type PtraceEvent struct {
	EventHeader
	Ret       int64
	Request   int64
	TargetPID uint32
}

func (e *PtraceEvent) Header() EventHeader { return e.EventHeader }

type ModuleLoadEvent struct {
	EventHeader
	Ret  int64
	Name string
}

func (e *ModuleLoadEvent) Header() EventHeader { return e.EventHeader }

type BPFLoadEvent struct {
	EventHeader
	Ret      int64
	ProgType uint32
}

func (e *BPFLoadEvent) Header() EventHeader { return e.EventHeader }

type MemfdEvent struct {
	EventHeader
	Ret   int64
	Name  string
	Flags uint32
}

func (e *MemfdEvent) Header() EventHeader { return e.EventHeader }

type ChmodEvent struct {
	EventHeader
	Ret  int64
	Path string
	Mode uint32
}

func (e *ChmodEvent) Header() EventHeader { return e.EventHeader }

type MmapExecEvent struct {
	EventHeader
	Ret  int64
	Addr uint64
	Len  uint64
	Prot uint32
}

func (e *MmapExecEvent) Header() EventHeader { return e.EventHeader }

type ProcProbeEvent struct {
	EventHeader
	Ret       int64
	TargetPID uint32
}

func (e *ProcProbeEvent) Header() EventHeader { return e.EventHeader }

type ProcMemOpenEvent struct {
	EventHeader
	Ret       int64
	TargetPID uint32
	TargetUID uint32
}

func (e *ProcMemOpenEvent) Header() EventHeader { return e.EventHeader }

const headerSize = 56 // 52 B of fields + 4 B trailing pad (uint64 alignment)

// parseRecord turns a raw ringbuf record into a typed Event.
// Wire format: 56-byte EventHeader, then int64 Ret, then per-type body.
func parseRecord(raw []byte) (Event, error) {
	if len(raw) < headerSize {
		return nil, fmt.Errorf("short record: %d bytes", len(raw))
	}
	le := binary.LittleEndian
	hdr := EventHeader{
		TsNs:     le.Uint64(raw[0:8]),
		CgroupID: le.Uint64(raw[8:16]),
		PID:      le.Uint32(raw[16:20]),
		PPID:     le.Uint32(raw[20:24]),
		UID:      le.Uint32(raw[24:28]),
		GID:      le.Uint32(raw[28:32]),
		Type:     EventType(le.Uint32(raw[32:36])),
	}
	copy(hdr.Comm[:], raw[36:52])
	// raw[52:56] is the trailing pad — skipped
	body := raw[headerSize:]
	switch hdr.Type {
	case EventExecAttempt:
		if len(body) < 8 {
			return nil, fmt.Errorf("exec_attempt: short body")
		}
		ret := int64(le.Uint64(body[0:8]))
		return &ExecAttemptEvent{EventHeader: hdr, Ret: ret, Filename: cstring(body[8:])}, nil
	case EventExec:
		if len(body) < 12 {
			return nil, fmt.Errorf("exec: short body")
		}
		ret := int64(le.Uint64(body[0:8]))
		n := le.Uint32(body[8:12])
		argv := body[12:]
		if int(n) > len(argv) {
			n = uint32(len(argv))
		}
		return &ExecEvent{EventHeader: hdr, Ret: ret, Argv: splitNul(argv[:n])}, nil
	case EventConnect:
		if len(body) < 28 { // 8 ret + 2 family + 2 port + 16 addr
			return nil, fmt.Errorf("connect: short body")
		}
		ret := int64(le.Uint64(body[0:8]))
		family := le.Uint16(body[8:10])
		port := le.Uint16(body[10:12])
		var ip netip.Addr
		switch family {
		case 2: // AF_INET
			ip = netip.AddrFrom4([4]byte{body[12], body[13], body[14], body[15]})
		case 10: // AF_INET6
			var a [16]byte
			copy(a[:], body[12:28])
			ip = netip.AddrFrom16(a)
		}
		return &ConnectEvent{EventHeader: hdr, Ret: ret, Family: family, DstIP: ip, DstPort: port}, nil
	case EventOpen:
		if len(body) < 12 {
			return nil, fmt.Errorf("open: short body")
		}
		ret := int64(le.Uint64(body[0:8]))
		flags := int32(le.Uint32(body[8:12]))
		return &OpenEvent{EventHeader: hdr, Ret: ret, Flags: flags, Path: cstring(body[12:])}, nil
	case EventClone:
		if len(body) < 16 {
			return nil, fmt.Errorf("clone: short body")
		}
		ret := int64(le.Uint64(body[0:8]))
		return &CloneEvent{EventHeader: hdr, Ret: ret, CloneFlags: le.Uint64(body[8:16])}, nil
	case EventUnshare:
		if len(body) < 16 {
			return nil, fmt.Errorf("unshare: short body")
		}
		ret := int64(le.Uint64(body[0:8]))
		return &UnshareEvent{EventHeader: hdr, Ret: ret, UnshareFlags: le.Uint64(body[8:16])}, nil
	case EventPtrace:
		if len(body) < 20 {
			return nil, fmt.Errorf("ptrace: short body")
		}
		ret := int64(le.Uint64(body[0:8]))
		req := int64(le.Uint64(body[8:16]))
		tgt := le.Uint32(body[16:20])
		return &PtraceEvent{EventHeader: hdr, Ret: ret, Request: req, TargetPID: tgt}, nil
	case EventModuleLoad:
		if len(body) < 8 {
			return nil, fmt.Errorf("module_load: short body")
		}
		ret := int64(le.Uint64(body[0:8]))
		return &ModuleLoadEvent{EventHeader: hdr, Ret: ret, Name: cstring(body[8:])}, nil
	case EventBPFLoad:
		if len(body) < 12 {
			return nil, fmt.Errorf("bpf: short body")
		}
		ret := int64(le.Uint64(body[0:8]))
		return &BPFLoadEvent{EventHeader: hdr, Ret: ret, ProgType: le.Uint32(body[8:12])}, nil
	case EventMemfd:
		if len(body) < 12 {
			return nil, fmt.Errorf("memfd: short body")
		}
		ret := int64(le.Uint64(body[0:8]))
		flags := le.Uint32(body[8:12])
		return &MemfdEvent{EventHeader: hdr, Ret: ret, Flags: flags, Name: cstring(body[12:])}, nil
	case EventChmod:
		if len(body) < 12 {
			return nil, fmt.Errorf("chmod: short body")
		}
		ret := int64(le.Uint64(body[0:8]))
		mode := le.Uint32(body[8:12])
		return &ChmodEvent{EventHeader: hdr, Ret: ret, Mode: mode, Path: cstring(body[12:])}, nil
	case EventMmapExec:
		if len(body) < 28 {
			return nil, fmt.Errorf("mmap: short body")
		}
		ret := int64(le.Uint64(body[0:8]))
		return &MmapExecEvent{
			EventHeader: hdr,
			Ret:         ret,
			Addr:        le.Uint64(body[8:16]),
			Len:         le.Uint64(body[16:24]),
			Prot:        le.Uint32(body[24:28]),
		}, nil
	case EventProcProbe:
		if len(body) < 12 {
			return nil, fmt.Errorf("proc_probe: short body")
		}
		ret := int64(le.Uint64(body[0:8]))
		return &ProcProbeEvent{EventHeader: hdr, Ret: ret, TargetPID: le.Uint32(body[8:12])}, nil
	case EventProcMemOpen:
		if len(body) < 16 {
			return nil, fmt.Errorf("proc_mem_open: short body")
		}
		ret := int64(le.Uint64(body[0:8]))
		return &ProcMemOpenEvent{
			EventHeader: hdr,
			Ret:         ret,
			TargetPID:   le.Uint32(body[8:12]),
			TargetUID:   le.Uint32(body[12:16]),
		}, nil
	default:
		return nil, fmt.Errorf("unknown event type: %d", hdr.Type)
	}
}

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func splitNul(b []byte) [][]byte {
	if len(b) == 0 {
		return nil
	}
	parts := bytes.Split(b, []byte{0})
	// Drop trailing empty from terminating \0
	if len(parts) > 0 && len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}
	return parts
}
