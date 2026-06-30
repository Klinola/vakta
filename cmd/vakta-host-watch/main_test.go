package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestScaffold(t *testing.T) {
	// First real test arrives in Task 2.
}

func TestConfigDefaults(t *testing.T) {
	cfg := defaultConfig()
	if cfg.SampleInterval != 60*time.Second {
		t.Errorf("SampleInterval default = %v, want 60s", cfg.SampleInterval)
	}
	if cfg.RetentionDays != 30 {
		t.Errorf("RetentionDays default = %d, want 30", cfg.RetentionDays)
	}
	if cfg.Cooldown != 3*time.Minute {
		t.Errorf("Cooldown default = %v, want 3m", cfg.Cooldown)
	}
	if cfg.Thresholds.Load1 != 20 {
		t.Errorf("Thresholds.Load1 default = %v, want 20", cfg.Thresholds.Load1)
	}
	if cfg.Thresholds.SwapSiMinKBPerSec != 1 {
		t.Errorf("Thresholds.SwapSiMinKBPerSec default = %d, want 1", cfg.Thresholds.SwapSiMinKBPerSec)
	}
	if cfg.Thresholds.VmstatBMin != 10 {
		t.Errorf("Thresholds.VmstatBMin default = %d, want 10", cfg.Thresholds.VmstatBMin)
	}
	if cfg.Thresholds.WindowSamples != 3 {
		t.Errorf("Thresholds.WindowSamples default = %d, want 3", cfg.Thresholds.WindowSamples)
	}
}

func TestConfigLoadYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host-watch.yaml")
	body := `
sample_interval: 30s
retention_days: 7
cooldown: 1m
db_path: /tmp/test.db
telegram:
  bot_token: yaml-tok
  chat_id: yaml-chat
thresholds:
  load1: 12.5
  swap_si_min_kb_s: 2
  vmstat_b_min: 5
  window_samples: 4
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.SampleInterval != 30*time.Second {
		t.Errorf("SampleInterval=%v, want 30s", cfg.SampleInterval)
	}
	if cfg.Telegram.BotToken != "yaml-tok" {
		t.Errorf("BotToken=%q", cfg.Telegram.BotToken)
	}
	if cfg.Thresholds.Load1 != 12.5 {
		t.Errorf("Load1=%v", cfg.Thresholds.Load1)
	}
}

func TestConfigEnvOverridesTGSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host-watch.yaml")
	body := "telegram:\n  bot_token: yaml-tok\n  chat_id: yaml-chat\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TG_BOT_TOKEN", "env-tok")
	t.Setenv("TG_CHAT_ID", "env-chat")
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Telegram.BotToken != "env-tok" {
		t.Errorf("BotToken=%q, want env-tok", cfg.Telegram.BotToken)
	}
	if cfg.Telegram.ChatID != "env-chat" {
		t.Errorf("ChatID=%q, want env-chat", cfg.Telegram.ChatID)
	}
}

func TestConfigMissingFileUsesDefaults(t *testing.T) {
	cfg, err := loadConfig("/no/such/path.yaml")
	if err != nil {
		t.Fatalf("missing config should NOT error; got: %v", err)
	}
	if cfg.SampleInterval != 60*time.Second {
		t.Errorf("expected defaults applied when file missing")
	}
}

func TestParseLoadavg(t *testing.T) {
	body, err := os.ReadFile("testdata/loadavg_busy")
	if err != nil {
		t.Fatal(err)
	}
	l1, l5, l15, err := parseLoadavg(string(body))
	if err != nil {
		t.Fatal(err)
	}
	if l1 != 39.63 || l5 != 39.50 || l15 != 35.17 {
		t.Errorf("got load %v %v %v", l1, l5, l15)
	}
}

func TestParseVmstatDelta(t *testing.T) {
	body1, _ := os.ReadFile("testdata/vmstat_sample_1")
	body2, _ := os.ReadFile("testdata/vmstat_sample_2")
	s1, err := parseVmstat(string(body1))
	if err != nil {
		t.Fatal(err)
	}
	s2, err := parseVmstat(string(body2))
	if err != nil {
		t.Fatal(err)
	}
	if s1.PswpIn != 12345 || s2.PswpIn != 12425 {
		t.Fatalf("pswpin: %d → %d", s1.PswpIn, s2.PswpIn)
	}
	// 80 pages × 4KB / 60s = 5 KB/s (using pageSize=4096; on real linux this is correct
	// for x86_64 default).
	kbPerSec := swapInKBPerSec(s1, s2, 60*time.Second, 4096)
	if kbPerSec != 5 {
		t.Errorf("swap-in KB/s = %d, want 5", kbPerSec)
	}
}

func TestParseMeminfo(t *testing.T) {
	body, _ := os.ReadFile("testdata/meminfo_thrash")
	mem, err := parseMeminfo(string(body))
	if err != nil {
		t.Fatal(err)
	}
	// MemTotal=16367812 KB, MemAvailable=9676128 KB → used = (total - available)/1024 MB ≈ 6535
	if mem.UsedMB < 6500 || mem.UsedMB > 6600 {
		t.Errorf("mem.UsedMB = %d, want ~6535", mem.UsedMB)
	}
	// SwapTotal-SwapFree = 4194300-2143372 = 2050928 KB ≈ 2002 MB
	if mem.SwapUsedMB < 1990 || mem.SwapUsedMB > 2010 {
		t.Errorf("mem.SwapUsedMB = %d, want ~2002", mem.SwapUsedMB)
	}
}

func TestReadTopProcsReturnsCurrentProcess(t *testing.T) {
	// We can't fixture /proc/<pid>/* easily; smoke-test the live reader.
	procs, err := readTopProcs(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(procs) == 0 {
		t.Fatal("expected at least one top proc on a live linux system")
	}
	// Each entry should have a non-empty name and a non-zero PID.
	for i, p := range procs {
		if p.PID <= 0 {
			t.Errorf("entry %d has PID %d", i, p.PID)
		}
		if strings.TrimSpace(p.Name) == "" {
			t.Errorf("entry %d has empty name", i)
		}
	}
	// Verify ordering: RSS+swap descending.
	for i := 1; i < len(procs); i++ {
		prevTotal := procs[i-1].RSSKB + procs[i-1].SwapKB
		curTotal := procs[i].RSSKB + procs[i].SwapKB
		if prevTotal < curTotal {
			t.Errorf("not sorted DESC at i=%d: prev=%d cur=%d", i, prevTotal, curTotal)
		}
	}
}

func TestSamplerRead(t *testing.T) {
	// Smoke: Sampler.Read() against live /proc should yield a sane Sample.
	s := NewSampler()
	first, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	if first.Ts == 0 {
		t.Error("Ts not set")
	}
	if first.Load1 < 0 || first.Load1 > 10000 {
		t.Errorf("Load1 looks wrong: %v", first.Load1)
	}
	if len(first.TopProcs) == 0 {
		t.Error("TopProcs empty")
	}
}

func TestStoreInsertAndQuery(t *testing.T) {
	st, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	samples := []Sample{
		{Ts: 100, Load1: 1.0, TopProcs: []TopProc{{PID: 1, Name: "init", RSSKB: 100}}},
		{Ts: 200, Load1: 5.0},
		{Ts: 300, Load1: 25.0},
	}
	for _, s := range samples {
		if err := st.Insert(s); err != nil {
			t.Fatalf("Insert %+v: %v", s, err)
		}
	}

	got, err := st.QueryRecent(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("QueryRecent(2) returned %d, want 2", len(got))
	}
	// Most recent first.
	if got[0].Ts != 300 || got[1].Ts != 200 {
		t.Errorf("ordering wrong: %v", []int64{got[0].Ts, got[1].Ts})
	}
	if got[1].TopProcs == nil {
		t.Logf("note: empty top_procs deserialized to nil slice — acceptable")
	}
}

func TestStorePrune(t *testing.T) {
	st, _ := openStore(":memory:")
	defer st.Close()
	for _, ts := range []int64{100, 200, 300, 400} {
		_ = st.Insert(Sample{Ts: ts})
	}
	if err := st.Prune(250); err != nil {
		t.Fatal(err)
	}
	got, _ := st.QueryRecent(10)
	if len(got) != 2 {
		t.Errorf("after Prune(250), expected 2 rows, got %d", len(got))
	}
	for _, s := range got {
		if s.Ts < 250 {
			t.Errorf("Prune left row Ts=%d", s.Ts)
		}
	}
}

func TestStoreInsertSurvivesEmptyTopProcs(t *testing.T) {
	st, _ := openStore(":memory:")
	defer st.Close()
	if err := st.Insert(Sample{Ts: 1, TopProcs: nil}); err != nil {
		t.Fatalf("Insert with nil TopProcs failed: %v", err)
	}
	got, _ := st.QueryRecent(1)
	if got[0].Ts != 1 {
		t.Error("expected Ts=1")
	}
}

func TestRingBufferFIFO(t *testing.T) {
	r := newRingBuffer(3)
	r.Push(Sample{Ts: 1})
	r.Push(Sample{Ts: 2})
	r.Push(Sample{Ts: 3})
	got := r.Snapshot()
	if len(got) != 3 || got[0].Ts != 1 || got[2].Ts != 3 {
		t.Errorf("snapshot order: %+v", got)
	}
	r.Push(Sample{Ts: 4})
	got = r.Snapshot()
	if len(got) != 3 || got[0].Ts != 2 || got[2].Ts != 4 {
		t.Errorf("after 4th push: %+v", got)
	}
}

func TestRingBufferNotFullYet(t *testing.T) {
	r := newRingBuffer(3)
	r.Push(Sample{Ts: 1})
	got := r.Snapshot()
	if len(got) != 1 || got[0].Ts != 1 {
		t.Errorf("Snapshot of partial ring: %+v", got)
	}
}

func TestEvaluatorFiresLoadHighSustained(t *testing.T) {
	cfg := defaultConfig()
	e := newEvaluator(cfg)
	// 3 samples all load1 > 20.
	samples := []Sample{
		{Ts: 100, Load1: 25},
		{Ts: 160, Load1: 30},
		{Ts: 220, Load1: 28},
	}
	fire, reason := e.Check(samples, time.Unix(220, 0))
	if !fire {
		t.Fatalf("expected fire, reason=%q", reason)
	}
	if !strings.Contains(reason, "load1") {
		t.Errorf("reason should mention load1: %q", reason)
	}
}

func TestEvaluatorDoesNotFireOnSingleSpike(t *testing.T) {
	cfg := defaultConfig()
	e := newEvaluator(cfg)
	// Only 1 of 3 samples is > 20.
	samples := []Sample{
		{Ts: 100, Load1: 5},
		{Ts: 160, Load1: 30},
		{Ts: 220, Load1: 7},
	}
	fire, _ := e.Check(samples, time.Unix(220, 0))
	if fire {
		t.Error("single spike should not fire")
	}
}

func TestEvaluatorFiresSwapThrashSignature(t *testing.T) {
	cfg := defaultConfig()
	e := newEvaluator(cfg)
	samples := []Sample{
		{Ts: 100, Load1: 5, SwapSiKBPerSec: 10, VmstatB: 15},
		{Ts: 160, Load1: 4, SwapSiKBPerSec: 5, VmstatB: 20},
		{Ts: 220, Load1: 3, SwapSiKBPerSec: 8, VmstatB: 12},
	}
	fire, reason := e.Check(samples, time.Unix(220, 0))
	if !fire {
		t.Fatalf("expected fire, reason=%q", reason)
	}
	if !strings.Contains(reason, "swap") {
		t.Errorf("reason should mention swap: %q", reason)
	}
}

func TestEvaluatorNotEnoughSamples(t *testing.T) {
	cfg := defaultConfig()
	e := newEvaluator(cfg)
	samples := []Sample{{Ts: 100, Load1: 100}}
	fire, _ := e.Check(samples, time.Unix(100, 0))
	if fire {
		t.Error("fewer than window_samples should not fire")
	}
}

func TestEvaluatorCooldown(t *testing.T) {
	cfg := defaultConfig()
	e := newEvaluator(cfg)
	hot := []Sample{
		{Ts: 100, Load1: 25}, {Ts: 160, Load1: 25}, {Ts: 220, Load1: 25},
	}
	fire1, _ := e.Check(hot, time.Unix(220, 0))
	if !fire1 {
		t.Fatal("first check should fire")
	}
	// 2 minutes later, still hot — within 3min cooldown.
	hot2 := []Sample{
		{Ts: 280, Load1: 25}, {Ts: 340, Load1: 25}, {Ts: 400, Load1: 25},
	}
	fire2, _ := e.Check(hot2, time.Unix(400, 0))
	if fire2 {
		t.Error("second check within cooldown should NOT fire")
	}
	// 4 minutes later (past 3min cooldown), still hot — should fire as continuing.
	hot3 := []Sample{
		{Ts: 460, Load1: 25}, {Ts: 520, Load1: 25}, {Ts: 580, Load1: 25},
	}
	fire3, reason3 := e.Check(hot3, time.Unix(580, 0))
	if !fire3 {
		t.Fatal("after cooldown expired, should fire again")
	}
	if !strings.Contains(reason3, "continuing") {
		t.Errorf("post-cooldown reason should include 'continuing': %q", reason3)
	}
}

func TestNotifierFormatMessage(t *testing.T) {
	sm := Sample{
		Ts: 1719750900, Load1: 39.6, VmstatWA: 74,
		MemUsedMB: 6500, SwapUsedMB: 2002, SwapSiKBPerSec: 80, VmstatB: 27,
		TopProcs: []TopProc{
			{PID: 1, Name: "gopls", RSSKB: 364068, SwapKB: 562156},
			{PID: 2, Name: "claude.exe", RSSKB: 345404, SwapKB: 81072},
		},
	}
	msg := formatTGMessage("worker", sm, "load1>20 sustained 3 samples")
	for _, s := range []string{"worker", "load=39.6", "wa=74", "swap=", "gopls", "claude.exe", "load1>20"} {
		if !strings.Contains(msg, s) {
			t.Errorf("message missing %q: %s", s, msg)
		}
	}
}

func TestNotifierPostsToTG(t *testing.T) {
	var hits int32
	var seenChatID string
	var seenText string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		body, _ := io.ReadAll(r.Body)
		v, _ := url.ParseQuery(string(body))
		seenChatID = v.Get("chat_id")
		seenText = v.Get("text")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	n := &notifier{
		apiBase: srv.URL,
		token:   "TOK",
		chatID:  "CHAT-42",
		client:  srv.Client(),
		// retryDelays tighter for test
		retryDelays: []time.Duration{1 * time.Millisecond},
	}
	if err := n.send("hello"); err != nil {
		t.Fatalf("send: %v", err)
	}
	if hits != 1 {
		t.Errorf("hits=%d, want 1", hits)
	}
	if seenChatID != "CHAT-42" {
		t.Errorf("chat_id=%q", seenChatID)
	}
	if seenText != "hello" {
		t.Errorf("text=%q", seenText)
	}
}

func TestNotifierRetriesOn5xx(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := atomic.AddInt32(&hits, 1)
		if c < 3 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	n := &notifier{
		apiBase: srv.URL, token: "TOK", chatID: "C",
		client: srv.Client(),
		retryDelays: []time.Duration{
			1 * time.Millisecond, 1 * time.Millisecond, 1 * time.Millisecond,
		},
	}
	if err := n.send("hi"); err != nil {
		t.Fatalf("send: %v", err)
	}
	if hits != 3 {
		t.Errorf("expected 3 attempts (2 fails + 1 success), got %d", hits)
	}
}

func TestNotifierDropsAfterMaxRetries(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(500)
	}))
	defer srv.Close()

	n := &notifier{
		apiBase: srv.URL, token: "TOK", chatID: "C",
		client: srv.Client(),
		retryDelays: []time.Duration{
			1 * time.Millisecond, 1 * time.Millisecond, 1 * time.Millisecond,
		},
	}
	err := n.send("hi")
	if err == nil {
		t.Error("expected error after exhausting retries")
	}
	if hits != 4 { // initial + 3 retries
		t.Errorf("expected 4 attempts, got %d", hits)
	}
}

func TestNotifierEmptyTokenIsNoop(t *testing.T) {
	n := &notifier{token: "", chatID: ""}
	if err := n.send("hi"); err != nil {
		t.Errorf("empty-token send should be no-op, got error: %v", err)
	}
}

func TestRunLoopFiresOnceThenCools(t *testing.T) {
	cfg := defaultConfig()
	cfg.SampleInterval = 50 * time.Millisecond
	cfg.Cooldown = 200 * time.Millisecond
	cfg.DBPath = ":memory:" // avoid fsync blocking the loop during the test window
	cfg.Thresholds.WindowSamples = 2

	var tgHits int32
	var mu sync.Mutex
	var lastBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&tgHits, 1)
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		lastBody = string(body)
		mu.Unlock()
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	cfg.Telegram.BotToken = "TOK"
	cfg.Telegram.ChatID = "C"

	// Override the sampler to feed synthetic always-over-threshold samples.
	fakeSamples := newFakeSampler([]Sample{
		{Load1: 50}, {Load1: 50}, {Load1: 50}, {Load1: 50}, {Load1: 50},
	})

	n := newNotifier(cfg)
	n.apiBase = srv.URL
	// Explicit no-proxy function so HTTP_PROXY env var doesn't route loopback
	// requests through Claude's outbound proxy (which can't reach 127.0.0.1).
	n.client = &http.Client{
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
		},
		Timeout: 2 * time.Second,
	}
	n.retryDelays = []time.Duration{1 * time.Millisecond}

	st, err := openStore(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	runLoop(ctx, cfg, fakeSamples, st, newEvaluator(cfg), n, "test-host")

	hits := atomic.LoadInt32(&tgHits)
	if hits < 1 {
		t.Fatalf("expected at least 1 TG alert, got %d", hits)
	}
	if hits > 3 {
		t.Errorf("too many alerts (cooldown not respected): %d", hits)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(lastBody, "load1") {
		t.Errorf("TG payload should mention reason: %s", lastBody)
	}

	// Verify samples were also persisted to SQLite.
	rows, _ := st.QueryRecent(20)
	if len(rows) < 2 {
		t.Errorf("expected ≥2 samples in DB, got %d", len(rows))
	}
}

// fakeSampler implements the sample-source interface used by runLoop in tests.
// It returns sequential canned samples and timestamps them with time.Now().
type fakeSampler struct {
	mu   sync.Mutex
	idx  int
	data []Sample
}

func newFakeSampler(data []Sample) *fakeSampler {
	return &fakeSampler{data: data}
}

func (f *fakeSampler) Read() (Sample, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.data) == 0 {
		return Sample{Ts: time.Now().Unix()}, nil
	}
	s := f.data[f.idx%len(f.data)]
	f.idx++
	s.Ts = time.Now().Unix() + int64(f.idx) // monotonic across calls
	return s, nil
}

func TestRunLoopRespectsContextCancel(t *testing.T) {
	cfg := defaultConfig()
	cfg.SampleInterval = 10 * time.Millisecond
	cfg.DBPath = ":memory:"
	st, _ := openStore(cfg.DBPath)
	defer st.Close()
	n := newNotifier(cfg) // no TG configured → no-op

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled
	done := make(chan struct{})
	go func() {
		runLoop(ctx, cfg, NewSampler(), st, newEvaluator(cfg), n, "h")
		close(done)
	}()
	select {
	case <-done:
		// good
	case <-time.After(500 * time.Millisecond):
		t.Fatal("runLoop did not honor canceled context")
	}
}
