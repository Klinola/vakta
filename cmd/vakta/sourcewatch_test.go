package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Klinola/vakta/config"
	"github.com/Klinola/vakta/internal/normalizer"
)

// syncBuffer is a bytes.Buffer safe for the watchdog goroutine to write while
// the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestWatchSourceLivenessReportsSilentSources covers the failure mode where the
// config claims a source is on and nothing ever arrives from it: the auditd
// netlink socket opens but the kernel has no audit rules loaded, and the k8s
// audit tailer waits forever for a file that only exists on control-plane
// nodes. Both used to look identical to a healthy, quiet node.
func TestWatchSourceLivenessReportsSilentSources(t *testing.T) {
	var buf syncBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	// No input channels, so no source ever emits.
	n := normalizer.New(nil, nil, nil, "test-node")
	defer n.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchSourceLiveness(ctx, n, config.SourcesSection{
		EBPF:     true,
		Auditd:   true,
		K8sAudit: true,
	}, "k8s", 10*time.Millisecond)

	deadline := time.After(3 * time.Second)
	for {
		out := buf.String()
		if strings.Contains(out, "auditd") &&
			strings.Contains(out, "k8s_audit") &&
			strings.Contains(out, "ebpf") {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("silent sources were never reported; log was:\n%s", out)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestWatchSourceLivenessIgnoresDisabledSources keeps the warning meaningful:
// a source nobody turned on is not a problem to report.
func TestWatchSourceLivenessIgnoresDisabledSources(t *testing.T) {
	var buf syncBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	n := normalizer.New(nil, nil, nil, "test-node")
	defer n.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// k8s_audit is on in config but the agent is in host mode, so it is not
	// actually running and must not be reported.
	go watchSourceLiveness(ctx, n, config.SourcesSection{
		EBPF: true, Auditd: false, K8sAudit: true,
	}, "host", 10*time.Millisecond)

	time.Sleep(300 * time.Millisecond)
	out := buf.String()
	if !strings.Contains(out, "ebpf") {
		t.Fatalf("enabled ebpf source was not reported; log was:\n%s", out)
	}
	if strings.Contains(out, "auditd") || strings.Contains(out, "k8s_audit") {
		t.Fatalf("disabled sources were reported; log was:\n%s", out)
	}
}
