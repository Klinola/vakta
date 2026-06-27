package probe

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestEventTypeConstants(t *testing.T) {
	if EventExecAttempt != 1 {
		t.Fatalf("EventExecAttempt = %d, want 1", EventExecAttempt)
	}
	if EventProcProbe != 13 {
		t.Fatalf("EventProcProbe = %d, want 13", EventProcProbe)
	}
}

// buildHeader returns 48 bytes that decode into an EventHeader.
func buildHeader(t EventType) []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, uint64(0xdeadbeef)) // ts
	_ = binary.Write(buf, binary.LittleEndian, uint32(123))        // pid
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))          // ppid
	_ = binary.Write(buf, binary.LittleEndian, uint32(1000))       // uid
	_ = binary.Write(buf, binary.LittleEndian, uint32(1000))       // gid
	_ = binary.Write(buf, binary.LittleEndian, uint32(t))          // type
	var comm [16]byte
	copy(comm[:], "test\x00")
	buf.Write(comm[:])
	buf.Write(make([]byte, 4)) // trailing pad to 8-byte alignment
	return buf.Bytes()
}

func TestParseRecord_HeaderSize(t *testing.T) {
	got := unsafe.Sizeof(EventHeader{})
	if got != 48 {
		t.Fatalf("sizeof(EventHeader) = %d, want 48", got)
	}
}

func TestParseRecord_ExecAttempt(t *testing.T) {
	rec := append(buildHeader(EventExecAttempt), append([]byte("/bin/ls"), 0)...)
	ev, err := parseRecord(rec)
	if err != nil {
		t.Fatalf("parseRecord: %v", err)
	}
	exec, ok := ev.(*ExecAttemptEvent)
	if !ok {
		t.Fatalf("got %T, want *ExecAttemptEvent", ev)
	}
	if exec.Filename != "/bin/ls" {
		t.Fatalf("Filename = %q, want /bin/ls", exec.Filename)
	}
	if exec.PID != 123 {
		t.Fatalf("PID = %d", exec.PID)
	}
}

func TestParseRecord_Exec(t *testing.T) {
	argv := []byte("ls\x00-la\x00/tmp\x00")
	hdr := buildHeader(EventExec)
	// wire body: uint32 argv_len + argv bytes
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(argv)))
	rec := append(hdr, append(lenBuf[:], argv...)...)
	ev, err := parseRecord(rec)
	if err != nil {
		t.Fatalf("parseRecord: %v", err)
	}
	e, ok := ev.(*ExecEvent)
	if !ok {
		t.Fatalf("got %T", ev)
	}
	if len(e.Argv) != 3 {
		t.Fatalf("argv split: got %d parts, want 3", len(e.Argv))
	}
}

func TestParseRecord_Connect(t *testing.T) {
	hdr := buildHeader(EventConnect)
	// Wire: u16 family, u16 dport, [16]byte addr
	body := make([]byte, 2+2+16)
	binary.LittleEndian.PutUint16(body[0:2], 2) // AF_INET
	binary.LittleEndian.PutUint16(body[2:4], 443)
	body[4], body[5], body[6], body[7] = 1, 1, 1, 1 // 1.1.1.1
	rec := append(hdr, body...)
	ev, err := parseRecord(rec)
	if err != nil {
		t.Fatalf("parseRecord: %v", err)
	}
	c, ok := ev.(*ConnectEvent)
	if !ok {
		t.Fatalf("got %T", ev)
	}
	if c.DstPort != 443 {
		t.Fatalf("DstPort = %d", c.DstPort)
	}
	if !c.DstIP.IsValid() || c.DstIP.String() != "1.1.1.1" {
		t.Fatalf("DstIP = %s", c.DstIP)
	}
}

func TestParseRecord_UnknownType(t *testing.T) {
	hdr := buildHeader(EventType(99))
	_, err := parseRecord(hdr)
	if err == nil {
		t.Fatal("expected error for unknown event type")
	}
}
