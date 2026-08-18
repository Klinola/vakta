package main

import (
	"os"
	"testing"
)

func TestResolveHostPrefersConfigThenNodeEnv(t *testing.T) {
	t.Setenv(nodeNameEnv, "app-2")

	if got := resolveHost("explicit"); got != "explicit" {
		t.Errorf("configured name should win, got %q", got)
	}
	// The pod hostname is the reporter, not the machine; the injected node name
	// has to beat it.
	if got := resolveHost(""); got != "app-2" {
		hostname, _ := os.Hostname()
		t.Errorf("resolveHost = %q, want the injected node name app-2 (hostname is %q)", got, hostname)
	}
}

func TestResolveHostFallsBackToHostname(t *testing.T) {
	t.Setenv(nodeNameEnv, "")
	want, _ := os.Hostname()
	if got := resolveHost(""); got != want {
		t.Errorf("resolveHost = %q, want %q", got, want)
	}
}
