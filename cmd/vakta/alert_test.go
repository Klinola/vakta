package main

import (
	"strings"
	"testing"
	"time"

	"github.com/Klinola/vakta/internal/engine"
	"github.com/Klinola/vakta/internal/normalizer"
)

func kcoreMatch() engine.Match {
	return engine.Match{
		Rule: engine.Rule{
			ID:       "open-proc-kcore",
			Name:     "Kernel memory opened",
			Severity: "critical",
		},
		Event: normalizer.Event{
			Ts: time.Now(), Source: normalizer.SourceEBPF, Type: "OPEN",
			Host: "app-2", PID: 3869294, PPID: 4242, UID: 0, Comm: "lscpu",
			Ret:    -2,
			Detail: &normalizer.OpenDetail{Path: "/dev/mem"},
		},
		At: time.Now(),
	}
}

// TestBuildAMAlertCarriesTriageContext pins the fields an on-call reader needs
// to act on a P0 without looking anything up. The alert used to carry only comm
// and pid, which is why a critical "kernel memory access" page could not be
// told apart from a container's lscpu failing to open /dev/mem.
func TestBuildAMAlertCarriesTriageContext(t *testing.T) {
	a := buildAMAlert(kcoreMatch(), "prod")

	for k, want := range map[string]string{
		"path": "/dev/mem",
		"pid":  "3869294",
		"ppid": "4242",
		"uid":  "0",
		"ret":  "-2",
		"comm": "lscpu",
	} {
		if got := a.Annotations[k]; got != want {
			t.Errorf("annotation %s = %q, want %q", k, got, want)
		}
	}

	summary := a.Annotations["summary"]
	for _, want := range []string{"app-2", "lscpu", "pid=3869294", "path=/dev/mem", "failed"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary %q missing %q", summary, want)
		}
	}
	if d := a.Annotations["detail"]; !strings.Contains(d, "/dev/mem") {
		t.Errorf("detail annotation = %q", d)
	}
}

// TestBuildAMAlertLabelsStayLowCardinality keeps per-process values out of the
// label set: labels are the alert identity Alertmanager groups and dedups on,
// so a pid in there would defeat grouping and repeat suppression.
func TestBuildAMAlertLabelsStayLowCardinality(t *testing.T) {
	a := buildAMAlert(kcoreMatch(), "prod")
	want := map[string]string{
		"alertname": "Kernel memory opened", "severity": "P0",
		"vakta_severity": "critical", "rule_id": "open-proc-kcore",
		"event_type": "OPEN", "cluster": "prod", "node": "app-2",
	}
	if len(a.Labels) != len(want) {
		t.Fatalf("labels = %v, want exactly %v", a.Labels, want)
	}
	for k, v := range want {
		if a.Labels[k] != v {
			t.Errorf("label %s = %q, want %q", k, a.Labels[k], v)
		}
	}
}

func TestEventTargetPerDetailType(t *testing.T) {
	cases := []struct {
		name   string
		detail any
		want   string
	}{
		{"open", &normalizer.OpenDetail{Path: "/etc/shadow"}, "path=/etc/shadow"},
		{"exec", &normalizer.ExecDetail{Argv: []string{"sh", "-c"}}, "argv0=sh"},
		{"module", &normalizer.ModuleDetail{Name: "rootkit"}, "module=rootkit"},
		{"none", nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := eventTarget(normalizer.Event{Detail: c.detail}); got != c.want {
				t.Fatalf("eventTarget = %q, want %q", got, c.want)
			}
		})
	}
}
