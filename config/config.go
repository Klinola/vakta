// Package config loads and validates vakta's YAML configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Agent      AgentSection    `yaml:"agent"`
	Sources    SourcesSection  `yaml:"sources"`
	RulesDir   string          `yaml:"rules_dir"`
	ActionsDir string          `yaml:"actions_dir"`
	Outputs    OutputsSection  `yaml:"outputs"`
	Storage    StorageSection  `yaml:"storage"`
	UI         UISection       `yaml:"ui"`
	Playbook   PlaybookSection `yaml:"playbook"`
	Log        LogSection      `yaml:"log"`
}

type AgentSection struct {
	Mode     string `yaml:"mode"`      // host | k8s
	NodeName string `yaml:"node_name"` // defaults to hostname when empty
}

type SourcesSection struct {
	EBPF        bool   `yaml:"ebpf"`
	Auditd      bool   `yaml:"auditd"`
	K8sAudit    bool   `yaml:"k8s_audit"`
	K8sAuditLog string `yaml:"k8s_audit_log"`
}

type OutputsSection struct {
	Alertmanager      string        `yaml:"alertmanager"`
	Loki              string        `yaml:"loki"`
	LokiFlushInterval time.Duration `yaml:"loki_flush_interval"`
	LokiBatchSize     int           `yaml:"loki_batch_size"`
}

type StorageSection struct {
	SQLitePath    string `yaml:"sqlite_path"`
	RetentionDays int    `yaml:"retention_days"`
}

type UISection struct {
	Enabled  bool   `yaml:"enabled"`
	Addr     string `yaml:"addr"`
	Auth     string `yaml:"auth"` // none | basic
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type PlaybookSection struct {
	AllowExecRun bool `yaml:"allow_exec_run"`
	DryRun       bool `yaml:"dry_run"`
}

type LogSection struct {
	Level  string `yaml:"level"`  // debug | info | warn | error
	Format string `yaml:"format"` // json | text
}

// Load reads and validates a YAML config file. Missing fields get defaults.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	c := &Config{}
	applyDefaults(c)
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	// Re-apply defaults for any fields YAML left at zero value
	applyDefaults(c)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func applyDefaults(c *Config) {
	if c.Agent.Mode == "" {
		c.Agent.Mode = "host"
	}
	if !c.Sources.EBPF && !c.Sources.Auditd && !c.Sources.K8sAudit {
		c.Sources.EBPF = true
		c.Sources.Auditd = true
	}
	if c.Sources.K8sAuditLog == "" {
		c.Sources.K8sAuditLog = "/var/log/k8s-audit.log"
	}
	if c.RulesDir == "" {
		c.RulesDir = "/etc/vakta/rules"
	}
	if c.ActionsDir == "" {
		c.ActionsDir = "/etc/vakta/actions"
	}
	if c.Outputs.LokiFlushInterval == 0 {
		c.Outputs.LokiFlushInterval = 5 * time.Second
	}
	if c.Outputs.LokiBatchSize == 0 {
		c.Outputs.LokiBatchSize = 100
	}
	if c.Storage.SQLitePath == "" {
		c.Storage.SQLitePath = "/var/lib/vakta/events.db"
	}
	if c.Storage.RetentionDays == 0 {
		c.Storage.RetentionDays = 30
	}
	if c.UI.Addr == "" {
		c.UI.Addr = ":9090"
	}
	if c.UI.Auth == "" {
		c.UI.Auth = "none"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "json"
	}
}

func (c *Config) Validate() error {
	switch c.Agent.Mode {
	case "host", "k8s":
	default:
		return fmt.Errorf("agent.mode: must be host|k8s, got %q", c.Agent.Mode)
	}
	switch c.UI.Auth {
	case "none":
	case "basic":
		if c.UI.Username == "" || c.UI.Password == "" {
			return errors.New("ui.auth=basic requires ui.username and ui.password")
		}
	default:
		return fmt.Errorf("ui.auth: must be none|basic, got %q", c.UI.Auth)
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level: must be debug|info|warn|error, got %q", c.Log.Level)
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		return fmt.Errorf("log.format: must be json|text, got %q", c.Log.Format)
	}
	if c.Storage.RetentionDays < 1 {
		return fmt.Errorf("storage.retention_days: must be >= 1, got %d", c.Storage.RetentionDays)
	}
	return nil
}
