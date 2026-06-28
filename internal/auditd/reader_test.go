package auditd

import (
	"testing"
	"time"
)

// TestRecordStructFieldsExposed sanity-checks that Record matches the
// shape the normalizer's convert_auditd.go expects.
func TestRecordStructFieldsExposed(t *testing.T) {
	r := Record{
		Seq:       1,
		Timestamp: time.Now(),
		Type:      "SYSCALL",
		Fields:    map[string]string{"pid": "100"},
	}
	if r.Type != "SYSCALL" || r.Fields["pid"] != "100" {
		t.Fatal()
	}
}

// TestParseAuditMessage_KeyValueFields verifies our key=value parser handles
// the most common auditd message shapes, including quoted values.
func TestParseAuditMessage_KeyValueFields(t *testing.T) {
	body := `audit(1697040000.123:42): arch=c000003e syscall=59 success=yes exit=0 ppid=1000 pid=2000 uid=0 comm="sshd" key="ssh_login"`
	r, err := parseAuditMessage(1300, body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.Type != "SYSCALL" {
		t.Errorf("Type=%q", r.Type)
	}
	if r.Fields["pid"] != "2000" || r.Fields["uid"] != "0" {
		t.Fatalf("fields=%+v", r.Fields)
	}
	if r.Fields["comm"] != `"sshd"` {
		t.Fatalf("comm=%q (expect quotes preserved for normalizer to strip)", r.Fields["comm"])
	}
	if r.Seq != 42 {
		t.Errorf("Seq=%d", r.Seq)
	}
}
