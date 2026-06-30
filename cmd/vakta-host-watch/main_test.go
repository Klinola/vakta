package main

import (
	"os"
	"path/filepath"
	"strings"
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
