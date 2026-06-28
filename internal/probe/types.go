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

const headerSize = 56 // 52 B of fields + 4 B trailing pad (uint64 alignment)

// parseRecord turns a raw ringbuf record into a typed Event.
// Wire format: 56-byte EventHeader followed by per-type body.
func parseRecord(raw []byte) (Event, error) {
	if len(raw) < headerSize {
		return nil, fmt.Errorf("short record: %d bytes", len(raw))
	}
	var hdr EventHeader
	if err := binary.Read(bytes.NewReader(raw[:headerSize]), binary.LittleEndian, &hdr); err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}
	body := raw[headerSize:]
	switch hdr.Type {
	case EventExecAttempt:
		return &ExecAttemptEvent{EventHeader: hdr, Filename: cstring(body)}, nil
	case EventExec:
		if len(body) < 4 {
			return nil, fmt.Errorf("exec: short body")
		}
		n := binary.LittleEndian.Uint32(body[:4])
		argv := body[4:]
		if int(n) > len(argv) {
			n = uint32(len(argv))
		}
		return &ExecEvent{EventHeader: hdr, Argv: splitNul(argv[:n])}, nil
	case EventConnect:
		if len(body) < 20 {
			return nil, fmt.Errorf("connect: short body")
		}
		family := binary.LittleEndian.Uint16(body[0:2])
		port := binary.LittleEndian.Uint16(body[2:4])
		var ip netip.Addr
		switch family {
		case 2: // AF_INET
			ip = netip.AddrFrom4([4]byte{body[4], body[5], body[6], body[7]})
		case 10: // AF_INET6
			var a [16]byte
			copy(a[:], body[4:20])
			ip = netip.AddrFrom16(a)
		}
		return &ConnectEvent{EventHeader: hdr, Family: family, DstIP: ip, DstPort: port}, nil
	case EventOpen:
		if len(body) < 4 {
			return nil, fmt.Errorf("open: short body")
		}
		flags := int32(binary.LittleEndian.Uint32(body[:4]))
		return &OpenEvent{EventHeader: hdr, Flags: flags, Path: cstring(body[4:])}, nil
	case EventClone:
		if len(body) < 8 {
			return nil, fmt.Errorf("clone: short body")
		}
		return &CloneEvent{EventHeader: hdr, CloneFlags: binary.LittleEndian.Uint64(body[:8])}, nil
	case EventUnshare:
		if len(body) < 8 {
			return nil, fmt.Errorf("unshare: short body")
		}
		return &UnshareEvent{EventHeader: hdr, UnshareFlags: binary.LittleEndian.Uint64(body[:8])}, nil
	case EventPtrace:
		if len(body) < 12 {
			return nil, fmt.Errorf("ptrace: short body")
		}
		req := int64(binary.LittleEndian.Uint64(body[:8]))
		tgt := binary.LittleEndian.Uint32(body[8:12])
		return &PtraceEvent{EventHeader: hdr, Request: req, TargetPID: tgt}, nil
	case EventModuleLoad:
		if len(body) < 8 {
			return nil, fmt.Errorf("module_load: short body")
		}
		return &ModuleLoadEvent{EventHeader: hdr, Name: cstring(body[8:])}, nil
	case EventBPFLoad:
		if len(body) < 4 {
			return nil, fmt.Errorf("bpf: short body")
		}
		return &BPFLoadEvent{EventHeader: hdr, ProgType: binary.LittleEndian.Uint32(body[:4])}, nil
	case EventMemfd:
		if len(body) < 4 {
			return nil, fmt.Errorf("memfd: short body")
		}
		flags := binary.LittleEndian.Uint32(body[:4])
		return &MemfdEvent{EventHeader: hdr, Flags: flags, Name: cstring(body[4:])}, nil
	case EventChmod:
		if len(body) < 4 {
			return nil, fmt.Errorf("chmod: short body")
		}
		mode := binary.LittleEndian.Uint32(body[:4])
		return &ChmodEvent{EventHeader: hdr, Mode: mode, Path: cstring(body[4:])}, nil
	case EventMmapExec:
		if len(body) < 20 {
			return nil, fmt.Errorf("mmap: short body")
		}
		return &MmapExecEvent{
			EventHeader: hdr,
			Addr:        binary.LittleEndian.Uint64(body[0:8]),
			Len:         binary.LittleEndian.Uint64(body[8:16]),
			Prot:        binary.LittleEndian.Uint32(body[16:20]),
		}, nil
	case EventProcProbe:
		if len(body) < 4 {
			return nil, fmt.Errorf("proc_probe: short body")
		}
		return &ProcProbeEvent{EventHeader: hdr, TargetPID: binary.LittleEndian.Uint32(body[:4])}, nil
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
