package normalizer

import "time"

// AuditdRecordView is the minimal shape from internal/auditd needed by the
// normalizer. The real type lives in internal/auditd (Task 6) but we mirror it
// here so this package compiles standalone. The concrete auditd.Record has
// these same fields plus more; only this subset is consumed.
type AuditdRecordView struct {
	Seq       uint32
	Timestamp time.Time
	Type      string // "SYSCALL" | "PATH" | "EXECVE" | etc.
	Fields    map[string]string
}

// FromAuditd converts a buffered SYSCALL+PATH multi-record into a single Event.
// records must share Seq; the SYSCALL record carries pid/uid/comm, PATH carries
// the file path.
func FromAuditd(records []AuditdRecordView, host string) Event {
	if len(records) == 0 {
		return Event{}
	}
	first := records[0]
	ev := Event{
		Ts:     first.Timestamp,
		Source: SourceAuditd,
		Host:   host,
		Type:   "AUDIT_FIM",
	}
	var path, key, op string
	for _, r := range records {
		switch r.Type {
		case "SYSCALL":
			ev.PID = parseUint32(r.Fields["pid"])
			ev.PPID = parseUint32(r.Fields["ppid"])
			ev.UID = parseUint32(r.Fields["uid"])
			ev.GID = parseUint32(r.Fields["gid"])
			ev.Comm = trimQuotes(r.Fields["comm"])
			key = trimQuotes(r.Fields["key"])
		case "PATH":
			if p := trimQuotes(r.Fields["name"]); p != "" {
				path = p
			}
			if r.Fields["op"] != "" {
				op = r.Fields["op"]
			}
		}
	}
	ev.Detail = &AuditFIMDetail{Path: path, AuditKey: key, Op: op}
	return ev
}

func trimQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func parseUint32(s string) uint32 {
	var n uint32
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + uint32(c-'0')
	}
	return n
}
