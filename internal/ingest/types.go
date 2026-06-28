// Package ingest defines the wire format for cross-process event transport
// between vakta agents and the vakta hub.
package ingest

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Klinola/vakta/internal/normalizer"
)

// IngestRequest is the JSON body POSTed by agents to the hub.
type IngestRequest struct {
	Events []WireEvent `json:"events"`
}

// WireEvent is a JSON-serializable normalizer.Event.
// DetailType identifies which concrete Detail struct lives in DetailData.
// Valid DetailType values: "exec","connect","open","clone","unshare",
//   "ptrace","module","bpf","memfd","chmod","mmap","procprobe","auditfim","k8s", or "".
type WireEvent struct {
	ID         uint64          `json:"id"`
	Ts         time.Time       `json:"ts"`
	Source     uint8           `json:"source"`
	Type       string          `json:"type"`
	Host       string          `json:"host"`
	CgroupID   uint64          `json:"cgroup_id"`
	PID        uint32          `json:"pid"`
	PPID       uint32          `json:"ppid"`
	UID        uint32          `json:"uid"`
	GID        uint32          `json:"gid"`
	Comm       string          `json:"comm"`
	Ret        int64           `json:"ret"`
	DetailType string          `json:"detail_type"`
	DetailData json.RawMessage `json:"detail_data,omitempty"`
}

// ToWire converts a normalizer.Event to a WireEvent.
func ToWire(ev normalizer.Event) WireEvent {
	w := WireEvent{
		ID:       ev.ID,
		Ts:       ev.Ts,
		Source:   uint8(ev.Source),
		Type:     ev.Type,
		Host:     ev.Host,
		CgroupID: ev.CgroupID,
		PID:      ev.PID,
		PPID:     ev.PPID,
		UID:      ev.UID,
		GID:      ev.GID,
		Comm:     ev.Comm,
		Ret:      ev.Ret,
	}
	if ev.Detail == nil {
		return w
	}
	var (
		raw []byte
		err error
	)
	switch ev.Detail.(type) {
	case *normalizer.ExecDetail:
		w.DetailType = "exec"
	case *normalizer.ConnectDetail:
		w.DetailType = "connect"
	case *normalizer.OpenDetail:
		w.DetailType = "open"
	case *normalizer.CloneDetail:
		w.DetailType = "clone"
	case *normalizer.UnshareDetail:
		w.DetailType = "unshare"
	case *normalizer.PtraceDetail:
		w.DetailType = "ptrace"
	case *normalizer.ModuleDetail:
		w.DetailType = "module"
	case *normalizer.BPFLoadDetail:
		w.DetailType = "bpf"
	case *normalizer.MemfdDetail:
		w.DetailType = "memfd"
	case *normalizer.ChmodDetail:
		w.DetailType = "chmod"
	case *normalizer.MmapExecDetail:
		w.DetailType = "mmap"
	case *normalizer.ProcProbeDetail:
		w.DetailType = "procprobe"
	case *normalizer.AuditFIMDetail:
		w.DetailType = "auditfim"
	case *normalizer.K8sDetail:
		w.DetailType = "k8s"
	default:
		return w
	}
	raw, err = json.Marshal(ev.Detail)
	if err != nil {
		// Should not happen for well-formed Detail values; drop the detail
		// rather than the entire event.
		w.DetailType = ""
		return w
	}
	w.DetailData = raw
	return w
}

// FromWire converts a WireEvent back to a normalizer.Event.
func FromWire(w WireEvent) (normalizer.Event, error) {
	ev := normalizer.Event{
		ID:       w.ID,
		Ts:       w.Ts,
		Source:   normalizer.Source(w.Source),
		Type:     w.Type,
		Host:     w.Host,
		CgroupID: w.CgroupID,
		PID:      w.PID,
		PPID:     w.PPID,
		UID:      w.UID,
		GID:      w.GID,
		Comm:     w.Comm,
		Ret:      w.Ret,
	}
	if w.DetailType == "" {
		return ev, nil
	}
	var target any
	switch w.DetailType {
	case "exec":
		target = &normalizer.ExecDetail{}
	case "connect":
		target = &normalizer.ConnectDetail{}
	case "open":
		target = &normalizer.OpenDetail{}
	case "clone":
		target = &normalizer.CloneDetail{}
	case "unshare":
		target = &normalizer.UnshareDetail{}
	case "ptrace":
		target = &normalizer.PtraceDetail{}
	case "module":
		target = &normalizer.ModuleDetail{}
	case "bpf":
		target = &normalizer.BPFLoadDetail{}
	case "memfd":
		target = &normalizer.MemfdDetail{}
	case "chmod":
		target = &normalizer.ChmodDetail{}
	case "mmap":
		target = &normalizer.MmapExecDetail{}
	case "procprobe":
		target = &normalizer.ProcProbeDetail{}
	case "auditfim":
		target = &normalizer.AuditFIMDetail{}
	case "k8s":
		target = &normalizer.K8sDetail{}
	default:
		return ev, fmt.Errorf("ingest: unknown detail_type %q", w.DetailType)
	}
	if len(w.DetailData) > 0 {
		if err := json.Unmarshal(w.DetailData, target); err != nil {
			return ev, fmt.Errorf("ingest: unmarshal %s detail: %w", w.DetailType, err)
		}
	}
	ev.Detail = target
	return ev, nil
}
