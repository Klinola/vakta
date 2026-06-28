package main

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Klinola/vakta/internal/engine"
	"github.com/Klinola/vakta/internal/normalizer"
	"github.com/Klinola/vakta/internal/storage"
)

func TestAlertPipeline(t *testing.T) {
	f, err := os.CreateTemp("", "vakta-pipeline-*.db")
	if err != nil { t.Fatal(err) }
	f.Close()
	defer os.Remove(f.Name())

	db, err := storage.Open(f.Name(), 1)
	if err != nil { t.Fatal("storage:", err) }
	defer db.Close()

	eng, err := engine.New(nil)
	if err != nil { t.Fatal("engine:", err) }
	fmt.Printf("Loaded %d built-in rules\n", len(eng.Rules()))

	ctx := context.Background()

	cases := []struct {
		name        string
		event       normalizer.Event
		wantMatches int
		wantRuleID  string
	}{
		{
			name: "exec-from-tmpdir",
			event: normalizer.Event{
				Ts: time.Now(), Source: normalizer.SourceEBPF, Type: "EXEC", Host: "test",
				PID: 100, UID: 0, Comm: "sh",
				Detail: &normalizer.ExecDetail{Filename: "/tmp/malware.sh", Argv: []string{"/tmp/malware.sh"}},
			},
			wantMatches: 1, wantRuleID: "exec-from-tmpdir",
		},
		{
			name: "fim-ld-so-preload",
			event: normalizer.Event{
				Ts: time.Now(), Source: normalizer.SourceAuditd, Type: "AUDIT_FIM", Host: "test",
				PID: 200, UID: 0, Comm: "python3",
				Detail: &normalizer.AuditFIMDetail{Path: "/etc/ld.so.preload", AuditKey: "fim-preload"},
			},
			wantMatches: 1, wantRuleID: "fim-ld-so-preload",
		},
		{
			name: "connect-c2-port-4444",
			event: normalizer.Event{
				Ts: time.Now(), Source: normalizer.SourceEBPF, Type: "CONNECT", Host: "test",
				PID: 300, UID: 1000, Comm: "bash",
				Detail: &normalizer.ConnectDetail{DstPort: 4444, Family: 2},
			},
			wantMatches: 1, wantRuleID: "connect-to-known-c2-port",
		},
		{
			name: "k8s-secret-bulk-list",
			event: normalizer.Event{
				Ts: time.Now(), Source: normalizer.SourceK8sAudit, Type: "K8S_SECRET_ACCESS", Host: "test",
				Detail: &normalizer.K8sDetail{Verb: "list", Resource: "secrets", Username: "attacker"},
			},
			wantMatches: 1, wantRuleID: "k8s-secret-bulk-list",
		},
		{
			name: "fim-sudoers-modified",
			event: normalizer.Event{
				Ts: time.Now(), Source: normalizer.SourceAuditd, Type: "AUDIT_FIM", Host: "test",
				PID: 400, UID: 0, Comm: "tee",
				Detail: &normalizer.AuditFIMDetail{Path: "/etc/sudoers", AuditKey: "fim-sudoers"},
			},
			wantMatches: 1, wantRuleID: "fim-sudoers-modified",
		},
		{
			name: "suid-bit-set",
			event: normalizer.Event{
				Ts: time.Now(), Source: normalizer.SourceEBPF, Type: "CHMOD", Host: "test",
				PID: 500, UID: 0, Comm: "chmod",
				Detail: &normalizer.ChmodDetail{Path: "/tmp/shell", Mode: 0o4755, SUID: true},
			},
			wantMatches: 1, wantRuleID: "suid-bit-set",
		},
		{
			name: "git-push-negative",
			event: normalizer.Event{
				Ts: time.Now(), Source: normalizer.SourceEBPF, Type: "EXEC", Host: "test",
				PID: 600, UID: 1000, Comm: "git",
				Detail: &normalizer.ExecDetail{Filename: "/usr/bin/git", Argv: []string{"git", "push"}},
			},
			wantMatches: 0, wantRuleID: "",
		},
	}

	alertCount := 0
	for _, tc := range cases {
		matches := eng.Evaluate(tc.event)
		status := "PASS"
		detail := ""
		if len(matches) != tc.wantMatches {
			status = "FAIL"
			detail = fmt.Sprintf("got %d matches, want %d", len(matches), tc.wantMatches)
			t.Errorf("[%s] %s", tc.name, detail)
		} else if tc.wantRuleID != "" && len(matches) > 0 && matches[0].Rule.ID != tc.wantRuleID {
			status = "FAIL"
			detail = fmt.Sprintf("rule=%s, want %s", matches[0].Rule.ID, tc.wantRuleID)
			t.Errorf("[%s] %s", tc.name, detail)
		}
		for _, m := range matches {
			id, _ := db.InsertEvent(ctx, tc.event)
			_, _ = db.InsertAlert(ctx, storage.Alert{
				RuleID: m.Rule.ID, RuleName: m.Rule.Name, Severity: m.Rule.Severity,
				EventID: id, Status: "firing", FiredAt: time.Now(),
			})
			alertCount++
		}
		if detail != "" {
			fmt.Printf("  [%-30s] %s — %s\n", tc.name, status, detail)
		} else if len(matches) > 0 {
			fmt.Printf("  [%-30s] %s — matched: %s (%s)\n", tc.name, status, matches[0].Rule.ID, matches[0].Rule.Severity)
		} else {
			fmt.Printf("  [%-30s] %s — no match (correct)\n", tc.name, status)
		}
	}

	n, _ := db.CountAlerts(ctx)
	fmt.Printf("\nAlerts in DB: %d (expected %d)\n", n, int64(alertCount))
	if int(n) != alertCount {
		t.Errorf("alert DB count: got %d, want %d", n, alertCount)
	}
}
