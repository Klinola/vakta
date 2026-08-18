package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/Klinola/vakta/config"
	"github.com/Klinola/vakta/internal/normalizer"
)

// sourceSilenceInterval is how often the agent re-checks whether every enabled
// source is actually producing. The first check is deliberately a few minutes
// in: an idle node can legitimately emit nothing for a short while.
const sourceSilenceInterval = 5 * time.Minute

var sourceNames = map[normalizer.Source]string{
	normalizer.SourceEBPF:     "ebpf",
	normalizer.SourceAuditd:   "auditd",
	normalizer.SourceK8sAudit: "k8s_audit",
}

// watchSourceLiveness warns, on a timer, about any source that config turned on
// but which has never produced an event.
//
// Enabling a source is not the same as it working, and the failure is silent in
// both directions we have hit in production: the auditd netlink socket opens
// successfully and then stays empty forever unless the kernel has audit rules
// loaded, and the k8s audit tailer blocks waiting for a log file that only
// exists on control-plane nodes — the sole trace being one unstructured line
// from the tail library at startup. Either way the config claims coverage the
// deployment does not have, which is worse than not configuring the source at
// all.
func watchSourceLiveness(
	ctx context.Context,
	n *normalizer.Normalizer,
	sources config.SourcesSection,
	mode string,
	every time.Duration,
) {
	enabled := map[normalizer.Source]bool{
		normalizer.SourceEBPF:     sources.EBPF,
		normalizer.SourceAuditd:   sources.Auditd,
		normalizer.SourceK8sAudit: sources.K8sAudit && mode == "k8s",
	}

	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			counts := n.Counts()
			for src, on := range enabled {
				if on && counts[src] == 0 {
					slog.Warn("source enabled but has produced no events",
						"source", sourceNames[src],
						"silent_for", every.String())
				}
			}
		}
	}
}
