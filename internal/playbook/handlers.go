package playbook

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/vakta-project/vakta/internal/alertmanager"
	"github.com/vakta-project/vakta/internal/engine"
)

type handlerCtx struct {
	am           *alertmanager.Client
	allowExecRun bool
}

// runHandler dispatches a single rendered step to its handler.
func (h *handlerCtx) runHandler(ctx context.Context, s Step, params map[string]any, m engine.Match) (string, error) {
	switch s.Action {
	case "notify":
		return h.actNotify(ctx, params, m)
	case "network.block_ip":
		return h.actBlockIP(ctx, params)
	case "process.kill":
		return h.actKill(params)
	case "container.pause":
		return h.actContainerPause(ctx, params)
	case "storage.snapshot":
		return h.actSnapshot(params, m)
	case "exec.run":
		if !h.allowExecRun {
			return "", errors.New("exec.run disabled by config (allow_exec_run=false)")
		}
		return h.actExecRun(ctx, params)
	default:
		return "", fmt.Errorf("unknown action type: %s", s.Action)
	}
}

func (h *handlerCtx) actNotify(ctx context.Context, p map[string]any, m engine.Match) (string, error) {
	severity, _ := p["severity"].(string)
	message, _ := p["message"].(string)
	h.am.Send(ctx, []alertmanager.Alert{{
		Labels: map[string]string{
			"alertname": m.Rule.Name,
			"severity":  severity,
			"rule_id":   m.Rule.ID,
		},
		Annotations: map[string]string{"summary": message},
		StartsAt:    time.Now(),
	}})
	return "notify dispatched", nil
}

func (h *handlerCtx) actBlockIP(ctx context.Context, p map[string]any) (string, error) {
	ip, _ := p["ip"].(string)
	dir, _ := p["direction"].(string)
	tool, _ := p["tool"].(string)
	if tool == "" {
		tool = "iptables"
	}
	if dir == "" {
		dir = "INPUT"
	}
	var args []string
	switch tool {
	case "iptables":
		args = []string{"-I", dir, "-s", ip, "-j", "DROP"}
	case "nftables":
		args = []string{"add", "rule", "inet", "filter", dir, "ip", "saddr", ip, "drop"}
	default:
		return "", fmt.Errorf("unsupported tool: %s", tool)
	}
	cmd := exec.CommandContext(ctx, tool, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (h *handlerCtx) actKill(p map[string]any) (string, error) {
	pidAny, ok := p["pid"]
	if !ok {
		return "", errors.New("kill: missing pid")
	}
	pid, err := toInt(pidAny)
	if err != nil {
		return "", fmt.Errorf("kill: pid: %w", err)
	}
	sigName, _ := p["signal"].(string)
	sig := syscall.SIGTERM
	if sigName == "SIGKILL" {
		sig = syscall.SIGKILL
	}
	if err := syscall.Kill(pid, sig); err != nil {
		return "", fmt.Errorf("kill(%d, %v): %w", pid, sig, err)
	}
	return fmt.Sprintf("sent %s to %d", sigName, pid), nil
}

func (h *handlerCtx) actContainerPause(ctx context.Context, p map[string]any) (string, error) {
	cgID, _ := p["cgroup_id"].(string)
	if cgID == "" {
		return "", errors.New("container.pause: cgroup_id required")
	}
	// Container ID resolution from cgroup_id is platform-specific and outside this
	// minimal implementation; treat cgroup_id as a docker container ID directly.
	out, err := exec.CommandContext(ctx, "docker", "pause", cgID).CombinedOutput()
	return string(out), err
}

func (h *handlerCtx) actSnapshot(p map[string]any, m engine.Match) (string, error) {
	// Minimal v1: persist a stub snapshot record. Real implementation would
	// capture /proc/<pid>/{status,maps,fd}, /proc/<pid>/net/tcp, etc.
	return fmt.Sprintf("snapshot stub for pid=%d", m.Event.PID), nil
}

func (h *handlerCtx) actExecRun(ctx context.Context, p map[string]any) (string, error) {
	cmd, _ := p["command"].(string)
	if cmd == "" {
		return "", errors.New("exec.run: command required")
	}
	out, err := exec.CommandContext(ctx, "/bin/sh", "-c", cmd).CombinedOutput()
	return string(out), err
}

func toInt(v any) (int, error) {
	switch x := v.(type) {
	case int:
		return x, nil
	case int64:
		return int(x), nil
	case float64:
		return int(x), nil
	case string:
		return strconv.Atoi(x)
	}
	return 0, fmt.Errorf("cannot convert %T to int", v)
}
