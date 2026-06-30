# Smoke Test Runbook

How to run the vakta agent against a real host for end-to-end validation
without writing to the production sinks (alertmanager / loki).

## Run

```sh
go build -o /tmp/vakta-test ./cmd/vakta
sudo /tmp/vakta-test agent --config dev/configs/smoke.yaml
```

`dev/configs/smoke.yaml` (host-mode, eBPF on, all outputs blank, dry-run
playbook):

```yaml
agent:
  mode: host
  node_name: smoke-test
sources:
  ebpf: true
  auditd: false
  k8s_audit: false
rules_dir: ""
actions_dir: ""
outputs:
  alertmanager: ""
  loki: ""
storage:
  sqlite_path: /tmp/vakta-smoke.db
  retention_days: 1
ui:
  enabled: false
  addr: ":19090"
  auth: none
playbook:
  allow_exec_run: false
  dry_run: true
log:
  level: info
  format: text
```

## The agent does not auto-exit

This is the most important thing to know about smoke runs.

`vakta agent` is a daemon. Its main loop is `for { select { case <-ctx.Done():
return; case ev := <-n.Events(): handleEvent(...) } }` (`cmd/vakta/agent.go`).
There is no `run-for` flag, no retention-based auto-exit, no idle timeout.
Even with `ui.enabled: false` + no alertmanager + no loki + no stdin input,
the agent keeps running indefinitely, eating CPU on every eBPF event your
kernel emits.

**Smoke collateral cleanup is the operator's responsibility.** When done:

```sh
sudo pkill -TERM -f '/tmp/vakta-test agent'
```

`SIGTERM` triggers `ctx.cancel()` → graceful shutdown → eBPF maps released,
SQLite WAL flushed.

## Why this matters

On 2026-06-30 a smoke run was left going for 2 days 5 hours on the worker
box. The two agent processes (one per config file) accumulated 121 minutes
of CPU time, kept eBPF probes pinned in the kernel, and contributed to a
load=39.6 swap-thrashing incident that took down the dev cluster node.

The agent itself was working as designed; the cleanup was missed. This
runbook exists so the next time someone runs the smoke flow, they remember
to kill it when they're done.

## Future work

If you want smoke runs that auto-exit after N minutes (or after capturing
N events), open an issue: this would be a small Cobra flag
(`--run-for 5m` or `--event-budget 1000`) on the `agent` command. Not
implemented yet because the smoke flow is run rarely and by hand.
