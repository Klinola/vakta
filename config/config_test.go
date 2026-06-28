package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_DefaultValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("agent:\n  mode: host\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Agent.Mode != "host" {
		t.Errorf("Agent.Mode = %q, want host", c.Agent.Mode)
	}
	if c.UI.Addr != ":9090" {
		t.Errorf("UI.Addr = %q, want :9090 (default)", c.UI.Addr)
	}
	if c.Storage.RetentionDays != 30 {
		t.Errorf("Storage.RetentionDays = %d, want 30 (default)", c.Storage.RetentionDays)
	}
	if c.Outputs.LokiFlushInterval != 5*time.Second {
		t.Errorf("LokiFlushInterval = %v, want 5s (default)", c.Outputs.LokiFlushInterval)
	}
}

func TestLoad_RejectsInvalidMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("agent:\n  mode: bogus\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for mode=bogus")
	}
}

func TestLoad_RejectsBasicAuthWithoutCreds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("ui:\n  auth: basic\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for basic auth with no username/password")
	}
}

func TestLoad_ExecRunRequiresExplicitOptIn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("playbook:\n  allow_exec_run: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Playbook.AllowExecRun {
		t.Fatal("AllowExecRun should be true when set")
	}
}
