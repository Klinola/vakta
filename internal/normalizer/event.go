// Package normalizer merges eBPF, auditd, and k8s audit streams into a
// unified Event channel for downstream consumers.
package normalizer

import (
	"net/netip"
	"time"
)

// Source identifies which subsystem produced an event.
type Source uint8

const (
	SourceEBPF     Source = 1
	SourceAuditd   Source = 2
	SourceK8sAudit Source = 3
)

// Event is the unified record emitted by the normalizer. Fields not applicable
// to a source stay at zero value. Detail is one of the *Detail types below, or nil.
type Event struct {
	ID       uint64
	Ts       time.Time
	Source   Source
	Type     string
	Host     string
	CgroupID uint64
	PID      uint32
	PPID     uint32
	UID      uint32
	GID      uint32
	Comm     string
	Ret      int64
	Detail   any
}

// Detail types — one per event type. Pointer-typed so a nil Detail field is
// distinguishable from a zero-value Detail.

type ExecDetail struct {
	Filename string
	Argv     []string
}

type ConnectDetail struct {
	DstIP   netip.Addr
	DstPort uint16
	Family  uint16
	Errno   int32
}

type OpenDetail struct {
	Path  string
	Flags int32
}

type CloneDetail struct {
	CloneFlags uint64
}

type UnshareDetail struct {
	UnshareFlags uint64
}

type PtraceDetail struct {
	Request   int64
	TargetPID uint32
}

type ModuleDetail struct {
	Name string
}

type BPFLoadDetail struct {
	ProgType uint32
}

type MemfdDetail struct {
	Name  string
	Flags uint32
}

type ChmodDetail struct {
	Path string
	Mode uint32
	SUID bool
	SGID bool
}

type MmapExecDetail struct {
	Addr uint64
	Len  uint64
	Prot uint32
}

type ProcProbeDetail struct {
	TargetPID uint32
}

type AuditFIMDetail struct {
	Path     string
	AuditKey string
	Op       string
}

type K8sDetail struct {
	Verb      string
	Resource  string
	Namespace string
	Name      string
	Username  string
	SourceIP  string
}
