# vakta

**Linux runtime security agent** — eBPF probes + kernel audit + Kubernetes audit log, evaluated against CEL rules, with automated response actions and a built-in web UI.

[![Go 1.25](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![Status](https://img.shields.io/badge/status-v0.3.0--rc-orange)]()

---

## What it does

vakta sits on every Linux host and watches what actually happens at the kernel level — syscalls, file opens, network connections, privilege changes — without modifying your applications or kernel. Events flow through a CEL policy engine; matches fan out to Alertmanager, Loki, and a configurable playbook that can kill a process, block an IP, pause a container, or run an arbitrary command.

Three event sources, one unified pipeline:

```
eBPF syscall probes ─┐
kernel audit (auditd)─┼─► normalizer ─► CEL engine ─┬─► SQLite (30-day retention)
k8s audit log ───────┘                               ├─► Alertmanager
                                                     ├─► Loki
                                                     └─► playbook actions
                                                                │
                                           REST API + SSE stream + embedded React UI
```

---

## Deployment modes

### Standalone

One binary per host. Events stay local; UI and API are on `:9090`.

```
[host]
  vakta agent ──► SQLite + UI
```

### Hub + Agent (multi-node / multi-cluster)

Agents collect events and batch-forward to a central hub. The hub holds the single SQLite store, runs the CEL engine, and exposes the UI. Designed for Kubernetes DaemonSet + Deployment topology.

```
[node-1]  vakta agent ──┐
[node-2]  vakta agent ──┼── HTTP batch ──► vakta hub ──► SQLite + UI + Alertmanager
[node-3]  vakta agent ──┘                  :7070             :8080
```

---

## Quick start

### Docker (standalone)

```bash
docker run --rm --privileged --pid=host --network=host \
  -v /sys:/sys:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  ghcr.io/klinola/vakta:latest agent

# UI → http://localhost:9090
```

> Requires Linux kernel ≥ 5.8 with BTF enabled (`/sys/kernel/btf/vmlinux` must exist).

### Kubernetes (Helm)

```bash
helm install vakta deploy/helm \
  --namespace vakta --create-namespace \
  --set outputs.alertmanager=http://alertmanager.monitoring:9093
```

The Helm chart deploys vakta in hub+agent mode: a privileged DaemonSet on every node forwarding to a central hub Deployment.

---

## Rules

Rules are written in [CEL](https://cel.dev) — no DSL to learn.

```yaml
rules:
  - id: exec-from-tmpdir
    name: Executable launched from /tmp or /dev/shm
    severity: high
    source: ebpf
    event_type: EXEC
    condition: >
      detail.filename.startsWith("/tmp/") ||
      detail.filename.startsWith("/dev/shm/")
    tags: [execution, defense-evasion, T1059]

  - id: k8s-anonymous-access
    name: Kubernetes API accessed anonymously
    severity: warning
    source: k8s_audit
    event_type: K8S_AUDIT
    condition: >
      event.user == "system:anonymous" &&
      event.verb in ["get", "list", "watch"]
    tags: [discovery, k8s, T1613]
```

Built-in rules ship embedded in the binary and cover:

| Category | Examples |
|---|---|
| Execution | reverse shells, exec from /tmp, credential dumpers, recon tools |
| File integrity | sudoers, SSH keys, PAM config, system binaries, boot files, log tampering |
| Privilege escalation | SUID/SGID chmod, namespace escape, suspicious BPF load |
| Network | Tor exit nodes, known C2 ports, suspicious outbound |
| Kubernetes | anonymous API access, privileged pod creation, hostPath mounts |

User rules are additive — a rule with the same `id` overrides the built-in. Place YAML files in `rules_dir` (default `/etc/vakta/rules/`).

---

## Playbook actions

When a rule matches, vakta can do more than alert:

```yaml
# deploy/examples/actions/full_incident_response.yaml
actions:
  - id: isolate-and-alert
    steps:
      - action: network.block_ip   # iptables DROP on the offending IP
        params: { ip: "{{event.dst_ip}}" }
      - action: process.kill        # SIGKILL the offending PID
        params: { pid: "{{event.pid}}" }
      - action: storage.snapshot    # dump /proc/<pid>/fd before it's gone
        params: { pid: "{{event.pid}}", output_dir: /var/vakta/snapshots }
      - action: notify              # fire to Alertmanager
        params: { severity: critical }
```

Built-in action handlers: `notify`, `network.block_ip`, `process.kill`, `container.pause`, `storage.snapshot`, `exec.run`.

---

## Outputs

| Sink | Config key | Notes |
|---|---|---|
| Alertmanager | `outputs.alertmanager` | async POST; labels include `cluster`, `node`, `rule_id`, `event_type` |
| Loki | `outputs.loki` | structured log push per event |
| Web UI | `ui.addr` (default `:9090`) | embedded React SPA, dark theme, severity badges, SSE live stream |
| REST API | `/api/v1/events`, `/api/v1/alerts` | JSON + SSE stream |

---

## Configuration

```yaml
# Standalone agent
agent:
  node_name: "worker-01"
  cluster_name: "prod"

sources:
  ebpf: true
  auditd: true
  k8s_audit: false        # set to true + point at audit log path on API servers

rules_dir: /etc/vakta/rules

storage:
  sqlite_path: /var/lib/vakta/events.db
  retention_days: 30

outputs:
  alertmanager: "http://alertmanager:9093"
  loki: "http://loki:3100"

ui:
  enabled: true
  addr: ":9090"
```

See `deploy/examples/` for hub and agent-forwarder variants.

---

## Requirements

| Requirement | Notes |
|---|---|
| Linux kernel ≥ 5.8 | BTF required (`/sys/kernel/btf/vmlinux`) |
| Capabilities | `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`, `CAP_AUDIT_READ` |
| Architecture | x86_64, arm64 |

BPF objects are pre-compiled and embedded — no clang or kernel headers needed at runtime.

---

## Build from source

```bash
# Build web UI + Go binary
cd web && npm ci && npm run build && cd ..
CGO_ENABLED=0 go build -o bin/vakta ./cmd/vakta

# Run tests (no root required)
go test ./...

# eBPF integration tests (root required)
sudo -E go test -tags=integration ./internal/probe/
```

Recompile BPF objects (only if modifying `internal/probe/*.bpf.c`):

```bash
# Requires clang ≥ 14 + bpftool
go generate ./internal/probe/...
```

---

## vs. alternatives

| | vakta | Falco | Tetragon |
|---|---|---|---|
| Event sources | eBPF + auditd + k8s audit | eBPF / syscall | eBPF |
| Rule language | CEL | Falco rules (custom DSL) | Rego / Go |
| Response actions | built-in (kill, block, pause, snapshot) | plugin system | TracingPolicy hooks |
| Storage | SQLite (embedded) | none | none |
| Web UI | built-in | separate (Falco UI) | via Grafana |
| Multi-node mode | hub+agent (built-in) | external aggregation | external aggregation |
| Binary size | single static binary | multiple components | multiple components |
| License | Apache 2.0 | Apache 2.0 | Apache 2.0 |

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
