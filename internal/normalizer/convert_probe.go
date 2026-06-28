package normalizer

import (
	"bytes"
	"strings"
	"time"

	"github.com/vakta-project/vakta/internal/probe"
)

// FromProbe converts a probe.Event into the unified normalizer Event.
func FromProbe(p probe.Event, host string) Event {
	h := p.Header()
	ev := Event{
		Ts:       time.Unix(0, int64(h.TsNs)),
		Source:   SourceEBPF,
		Host:     host,
		CgroupID: h.CgroupID,
		PID:      h.PID, PPID: h.PPID, UID: h.UID, GID: h.GID,
		Comm: cstr(h.Comm[:]),
	}
	switch e := p.(type) {
	case *probe.ExecAttemptEvent:
		ev.Type = "EXEC_ATTEMPT"
		ev.Ret = e.Ret
		ev.Detail = &ExecDetail{Filename: e.Filename}
	case *probe.ExecEvent:
		ev.Type = "EXEC"
		ev.Ret = e.Ret
		argv := make([]string, 0, len(e.Argv))
		for _, b := range e.Argv {
			argv = append(argv, string(bytes.TrimRight(b, "\x00")))
		}
		ev.Detail = &ExecDetail{Argv: argv}
	case *probe.ConnectEvent:
		ev.Type = "CONNECT"
		ev.Ret = e.Ret
		ev.Detail = &ConnectDetail{
			DstIP: e.DstIP, DstPort: e.DstPort, Family: e.Family, Errno: int32(e.Ret),
		}
	case *probe.OpenEvent:
		ev.Type = "OPEN"
		ev.Ret = e.Ret
		ev.Detail = &OpenDetail{Path: e.Path, Flags: e.Flags}
	case *probe.CloneEvent:
		ev.Type = "CLONE"
		ev.Ret = e.Ret
		ev.Detail = &CloneDetail{CloneFlags: e.CloneFlags}
	case *probe.UnshareEvent:
		ev.Type = "UNSHARE"
		ev.Ret = e.Ret
		ev.Detail = &UnshareDetail{UnshareFlags: e.UnshareFlags}
	case *probe.PtraceEvent:
		ev.Type = "PTRACE"
		ev.Ret = e.Ret
		ev.Detail = &PtraceDetail{Request: e.Request, TargetPID: e.TargetPID}
	case *probe.ModuleLoadEvent:
		ev.Type = "MODULE_LOAD"
		ev.Ret = e.Ret
		ev.Detail = &ModuleDetail{Name: e.Name}
	case *probe.BPFLoadEvent:
		ev.Type = "BPF_LOAD"
		ev.Ret = e.Ret
		ev.Detail = &BPFLoadDetail{ProgType: e.ProgType}
	case *probe.MemfdEvent:
		ev.Type = "MEMFD"
		ev.Ret = e.Ret
		ev.Detail = &MemfdDetail{Name: e.Name, Flags: e.Flags}
	case *probe.ChmodEvent:
		ev.Type = "CHMOD"
		ev.Ret = e.Ret
		ev.Detail = &ChmodDetail{
			Path: e.Path, Mode: e.Mode,
			SUID: e.Mode&0o4000 != 0,
			SGID: e.Mode&0o2000 != 0,
		}
	case *probe.MmapExecEvent:
		ev.Type = "MMAP_EXEC"
		ev.Ret = e.Ret
		ev.Detail = &MmapExecDetail{Addr: e.Addr, Len: e.Len, Prot: e.Prot}
	case *probe.ProcProbeEvent:
		ev.Type = "PROC_PROBE"
		ev.Ret = e.Ret
		ev.Detail = &ProcProbeDetail{TargetPID: e.TargetPID}
	default:
		ev.Type = "UNKNOWN"
	}
	return ev
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return strings.TrimRight(string(b), "\x00")
}
