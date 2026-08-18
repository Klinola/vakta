package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Klinola/vakta/internal/alertmanager"
	"github.com/Klinola/vakta/internal/engine"
	"github.com/Klinola/vakta/internal/normalizer"
)

// detailAnnotationLimit caps the serialised detail so a pathological argv can't
// push a multi-kilobyte annotation into every downstream notifier.
const detailAnnotationLimit = 1024

// buildAMAlert renders one rule match as an Alertmanager alert.
//
// Labels carry only the low-cardinality fields — they are the alert's identity
// for grouping, dedup and repeat_interval, so per-process values must stay out
// of them. Everything needed to triage the alert goes in annotations instead:
// which file was touched, as whom, and whether the syscall even succeeded.
// Without those, a P0 reads as "comm X did something at pid N" and the only way
// to learn more is to look up the stored event, which is exactly what is
// unavailable when the hub is overloaded or the event has aged out.
func buildAMAlert(m engine.Match, cluster string) alertmanager.Alert {
	ev := m.Event
	target := eventTarget(ev)

	summary := fmt.Sprintf("[%s/%s] %s — %s pid=%d uid=%d",
		cluster, ev.Host, m.Rule.Name, ev.Comm, ev.PID, ev.UID)
	if target != "" {
		summary += " " + target
	}
	if ev.Ret < 0 {
		// A negative return means the syscall was refused; the process tried
		// and failed. Saying so on the alert line keeps a blocked attempt from
		// reading like a successful one.
		summary += fmt.Sprintf(" ret=%d (failed)", ev.Ret)
	}

	ann := map[string]string{
		"summary": summary,
		"description": fmt.Sprintf("rule=%s severity=%s type=%s",
			m.Rule.ID, m.Rule.Severity, ev.Type),
		"comm":      ev.Comm,
		"pid":       fmt.Sprint(ev.PID),
		"ppid":      fmt.Sprint(ev.PPID),
		"uid":       fmt.Sprint(ev.UID),
		"gid":       fmt.Sprint(ev.GID),
		"ret":       fmt.Sprint(ev.Ret),
		"cgroup_id": fmt.Sprint(ev.CgroupID),
	}
	if target != "" {
		k, v, _ := strings.Cut(target, "=")
		ann[k] = v
	}
	if d, err := json.Marshal(ev.Detail); err == nil && string(d) != "null" {
		s := string(d)
		if len(s) > detailAnnotationLimit {
			s = s[:detailAnnotationLimit] + "…(truncated)"
		}
		ann["detail"] = s
	}

	return alertmanager.Alert{
		Labels: map[string]string{
			"alertname":      m.Rule.Name,
			"severity":       severityToP(m.Rule.Severity),
			"vakta_severity": m.Rule.Severity,
			"rule_id":        m.Rule.ID,
			"event_type":     ev.Type,
			"cluster":        cluster,
			"node":           ev.Host,
		},
		Annotations: ann,
		StartsAt:    m.At,
	}
}

// eventTarget returns the single most useful "what did it act on" field for an
// event, as a key=value pair, or "" when the event type has no such field.
func eventTarget(ev normalizer.Event) string {
	switch d := ev.Detail.(type) {
	case *normalizer.OpenDetail:
		return "path=" + d.Path
	case *normalizer.ChmodDetail:
		return "path=" + d.Path
	case *normalizer.AuditFIMDetail:
		return "path=" + d.Path
	case *normalizer.ExecDetail:
		if d.Filename != "" {
			return "exe=" + d.Filename
		}
		if len(d.Argv) > 0 {
			return "argv0=" + d.Argv[0]
		}
	case *normalizer.ConnectDetail:
		return fmt.Sprintf("dst=%s:%d", d.DstIP, d.DstPort)
	case *normalizer.ModuleDetail:
		return "module=" + d.Name
	case *normalizer.MemfdDetail:
		return "memfd=" + d.Name
	case *normalizer.PtraceDetail:
		return fmt.Sprintf("target_pid=%d", d.TargetPID)
	case *normalizer.ProcProbeDetail:
		return fmt.Sprintf("target_pid=%d", d.TargetPID)
	case *normalizer.ProcMemOpenDetail:
		return fmt.Sprintf("target_pid=%d", d.TargetPID)
	case *normalizer.K8sDetail:
		return fmt.Sprintf("k8s=%s/%s by %s", d.Verb, d.Resource, d.Username)
	}
	return ""
}
