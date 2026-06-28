package normalizer

import (
	"github.com/vakta-project/vakta/internal/auditd"
)

// AuditdRecord is re-exported here for the normalizer's input signature.
type AuditdRecord = auditd.Record

// FromAuditd converts a buffered SYSCALL+PATH multi-record into one Event.
func FromAuditd(records []AuditdRecord, host string) Event {
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
