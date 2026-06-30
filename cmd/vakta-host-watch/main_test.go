package main

import (
	"os"
	"path/filepath"
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
