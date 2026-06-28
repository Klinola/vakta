package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("vakta")) {
		t.Fatalf("version output missing 'vakta': %q", out.String())
	}
}

func TestRulesLint_GoodRule(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "g.yaml")
	_ = os.WriteFile(good, []byte(`
rules:
  - id: r1
    name: R1
    severity: info
    condition: event.uid == 0
`), 0o644)
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"rules", "lint", good})
	if err := root.Execute(); err != nil {
		t.Fatalf("lint: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("OK")) {
		t.Fatalf("expected OK in output: %q", out.String())
	}
}

func TestRulesLint_BadRule(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "b.yaml")
	_ = os.WriteFile(bad, []byte(`
rules:
  - id: r1
    name: R1
    severity: info
    condition: this is not CEL
`), 0o644)
	root := newRootCmd()
	root.SetArgs([]string{"rules", "lint", bad})
	if err := root.Execute(); err == nil {
		t.Fatal("expected error for invalid CEL")
	}
}
