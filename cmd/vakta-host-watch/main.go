// Package main implements vakta-host-watch, a host overload early-warning
// daemon. See docs/superpowers/specs/2026-06-30-vakta-host-watch-design.md
// in the Taberna repo for the design.
package main

import (
	"errors"
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("vakta-host-watch starting (scaffold)")
	os.Exit(0)
}

type Config struct {
	SampleInterval time.Duration `yaml:"sample_interval"`
	RetentionDays  int           `yaml:"retention_days"`
	Cooldown       time.Duration `yaml:"cooldown"`
	DBPath         string        `yaml:"db_path"`

	Telegram struct {
		BotToken string `yaml:"bot_token"`
		ChatID   string `yaml:"chat_id"`
	} `yaml:"telegram"`

	Thresholds struct {
		Load1              float64 `yaml:"load1"`
		SwapSiMinKBPerSec  int64   `yaml:"swap_si_min_kb_s"`
		VmstatBMin         int64   `yaml:"vmstat_b_min"`
		WindowSamples      int     `yaml:"window_samples"`
	} `yaml:"thresholds"`
}

func defaultConfig() Config {
	var c Config
	c.SampleInterval = 60 * time.Second
	c.RetentionDays = 30
	c.Cooldown = 3 * time.Minute
	c.DBPath = expandHome("~/.vakta/host-watch.db")
	c.Thresholds.Load1 = 20
	c.Thresholds.SwapSiMinKBPerSec = 1
	c.Thresholds.VmstatBMin = 10
	c.Thresholds.WindowSamples = 3
	return c
}

func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return applyEnvOverrides(cfg), nil
		}
		return cfg, err
	}
	if err := yaml.Unmarshal(body, &cfg); err != nil {
		return cfg, err
	}
	return applyEnvOverrides(cfg), nil
}

func applyEnvOverrides(cfg Config) Config {
	if v := os.Getenv("TG_BOT_TOKEN"); v != "" {
		cfg.Telegram.BotToken = v
	}
	if v := os.Getenv("TG_CHAT_ID"); v != "" {
		cfg.Telegram.ChatID = v
	}
	return cfg
}

func expandHome(p string) string {
	if len(p) > 1 && p[:2] == "~/" {
		if h, err := os.UserHomeDir(); err == nil {
			return h + p[1:]
		}
	}
	return p
}
