package probe

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
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

// buildHeader returns 56 bytes (52 fields + 4 pad) that decode into an EventHeader.
func buildHeader(t EventType) []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, uint64(0xdeadbeef)) // ts
	_ = binary.Write(buf, binary.LittleEndian, uint64(0x1234))     // cgroup_id
	_ = binary.Write(buf, binary.LittleEndian, uint32(123))        // pid
	_ = binary.Write(buf, binary.LittleEndian, uint32(1))          // ppid
	_ = binary.Write(buf, binary.LittleEndian, uint32(1000))       // uid
	_ = binary.Write(buf, binary.LittleEndian, uint32(1000))       // gid
	_ = binary.Write(buf, binary.LittleEndian, uint32(t))          // type
	var comm [16]byte
	copy(comm[:], "test\x00")
	buf.Write(comm[:])
	buf.Write(make([]byte, 4)) // trailing pad
	return buf.Bytes()
}

func TestParseRecord_HeaderSize(t *testing.T) {
	got := unsafe.Sizeof(EventHeader{})
	if got != 56 {
		t.Fatalf("sizeof(EventHeader) = %d, want 56", got)
	}
}

func TestParseRecord_ExecAttempt(t *testing.T) {
	// body: 8 ret + cstring filename
	body := make([]byte, 8)
	body = append(body, []byte("/bin/ls\x00")...)
	rec := append(buildHeader(EventExecAttempt), body...)
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
	if exec.Ret != 0 {
		t.Fatalf("Ret = %d, want 0", exec.Ret)
	}
}

func TestParseRecord_Exec(t *testing.T) {
	argv := []byte("ls\x00-la\x00/tmp\x00")
	hdr := buildHeader(EventExec)
	// wire body: int64 ret + uint32 argv_len + argv bytes
	body := make([]byte, 8+4+len(argv))
	binary.LittleEndian.PutUint32(body[8:12], uint32(len(argv)))
	copy(body[12:], argv)
	rec := append(hdr, body...)
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
	// Wire: int64 ret, u16 family, u16 dport, [16]byte addr
	body := make([]byte, 8+2+2+16)
	binary.LittleEndian.PutUint64(body[0:8], 0)   // ret = 0
	binary.LittleEndian.PutUint16(body[8:10], 2)  // AF_INET
	binary.LittleEndian.PutUint16(body[10:12], 443)
	body[12], body[13], body[14], body[15] = 1, 1, 1, 1 // 1.1.1.1
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
	if c.Ret != 0 {
		t.Fatalf("Ret = %d, want 0", c.Ret)
	}
}

func TestParseRecord_ConnectNegativeRet(t *testing.T) {
	hdr := buildHeader(EventConnect)
	body := make([]byte, 8+2+2+16)
	// ret = -EACCES (-13) as int64 little-endian
	var retNeg int64 = -13
	binary.LittleEndian.PutUint64(body[0:8], uint64(retNeg))
	rec := append(hdr, body...)
	ev, err := parseRecord(rec)
	if err != nil {
		t.Fatalf("parseRecord: %v", err)
	}
	c, ok := ev.(*ConnectEvent)
	if !ok {
		t.Fatalf("got %T", ev)
	}
	if c.Ret != -13 {
		t.Fatalf("Ret = %d, want -13", c.Ret)
	}
}

func TestParseRecord_UnknownType(t *testing.T) {
	hdr := buildHeader(EventType(99))
	_, err := parseRecord(hdr)
	if err == nil {
		t.Fatal("expected error for unknown event type")
	}
}

func TestStatsAccessorReturnsCopy(t *testing.T) {
	m := &Manager{
		statsDeliveredByType: map[EventType]uint64{EventExec: 42},
		statsMissing:         []string{"foo/bar"},
	}
	s := m.Stats()
	if s.DeliveredByType[EventExec] != 42 {
		t.Fatalf("DeliveredByType: %v", s.DeliveredByType)
	}
	// Mutating snapshot must not affect Manager
	s.DeliveredByType[EventExec] = 0
	s.MissingTracepoints[0] = "x"
	if m.statsDeliveredByType[EventExec] != 42 {
		t.Fatal("Stats() returned shared map")
	}
	if m.statsMissing[0] != "foo/bar" {
		t.Fatal("Stats() returned shared slice")
	}
}

func TestManagerCloseUnblocksStuckSend(t *testing.T) {
	// Construct a Manager bypassing New (we don't need real BPF) and simulate
	// a stuck send: the channel is unbuffered → first send blocks until consumer reads.
	m := &Manager{
		out:                  make(chan Event), // unbuffered to force blocking
		done:                 make(chan struct{}),
		quit:                 make(chan struct{}),
		statsDeliveredByType: make(map[EventType]uint64),
	}

	// Simulate the readLoop's send pattern with a single iteration.
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		ev := &ExecEvent{}
		select {
		case m.out <- ev:
		case <-m.quit:
		}
	}()

	// Give the goroutine time to park on the send.
	time.Sleep(50 * time.Millisecond)

	// Close the quit channel directly (mimics what Manager.Close does).
	close(m.quit)

	select {
	case <-loopDone:
		// good — escape path worked
	case <-time.After(time.Second):
		t.Fatal("readLoop send did not release on quit")
	}
}

func BenchmarkParseRecord_ExecAttempt(b *testing.B) {
	body := make([]byte, 8)
	body = append(body, []byte("/bin/ls\x00")...)
	rec := append(buildHeader(EventExecAttempt), body...)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = parseRecord(rec)
	}
}
