# vakta

Linux runtime event-processing agent. eBPF syscall probes + kernel audit (netlink) + Kubernetes audit log feed a CEL policy engine; matches persist to SQLite, fan out to Alertmanager / Loki, and trigger configurable response actions. Single Go binary, embedded React UI on `:9090`.

## Status

`v0.3.0` candidate. Probe layer (`internal/probe/`, kernel-side BPF) and full event-processing pipeline (normalizer, engine, storage, sinks, playbook, REST API + SSE, web UI) are implemented and tested.

## Requirements

- Linux kernel ≥ 5.8 with `CONFIG_DEBUG_INFO_BTF=y` (check `/sys/kernel/btf/vmlinux` exists) — required for the eBPF probe layer
- Go ≥ 1.25
- clang/LLVM ≥ 14 (only for `go generate`; pre-built objects ship in the binary)
- `bpftool` (only to refresh `vmlinux.h`)
- Capabilities at runtime: `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`, `CAP_AUDIT_READ`

Install build deps on Ubuntu 22.04+:
```bash
sudo apt-get install -y clang llvm libelf-dev linux-tools-common linux-tools-$(uname -r)
```

## Build

```bash
make build                              # builds web SPA + Go binary into bin/vakta
# or step by step:
cd web && npm ci && npm run build       # build the React UI into web/dist/
go generate ./internal/probe/...        # bpf2go compiles probe.bpf.c
CGO_ENABLED=0 go build -o bin/vakta ./cmd/vakta
```

## Run

```bash
sudo bin/vakta agent --config /etc/vakta/config.yaml
# UI: http://localhost:9090
```

Sample config: see `config/default.yaml`. Defaults to host mode with eBPF + auditd enabled, no outputs.

## Architecture

```
eBPF probe ─┐
auditd     ─┼─► normalizer ─► engine (CEL) ─┬─► SQLite store
k8s audit  ─┘                                ├─► alertmanager
                                             ├─► loki
                                             └─► playbook (notify/block/kill/snapshot/...)
                                                          │
                                            REST API + SSE + embedded React UI
```

Components:
- `internal/probe/` — eBPF kernel programs + Go ringbuf reader (34 SEC programs, 13 event types)
- `internal/auditd/` — kernel audit netlink reader
- `internal/k8saudit/` — Kubernetes API server audit log tailer
- `internal/normalizer/` — fan-in of all three sources into a unified `Event` channel
- `internal/engine/` — CEL rule evaluator (built-in rules embedded; user rules from disk)
- `internal/storage/` — SQLite persistence (events, alerts, action runs) with retention pruning
- `internal/alertmanager/` — async POST client to Prometheus Alertmanager
- `internal/loki/` — async push to Loki
- `internal/playbook/` — action engine with 6 built-in handlers (`notify`, `network.block_ip`, `process.kill`, `container.pause`, `storage.snapshot`, `exec.run`)
- `internal/api/` — REST API (`/api/v1/...`), SSE event stream, embedded web UI

## Test

```bash
make test                               # all unit tests, no privileges
sudo -E go test -tags=integration -count=1 ./internal/probe/   # eBPF integration; needs root
```

## Deployment

- **systemd:** `deploy/systemd/vakta.service`
- **Docker:** `Dockerfile` (multi-stage; builds web + Go + distroless runtime)
- **Kubernetes:** `deploy/helm/` (DaemonSet, ConfigMaps for config + rules + actions, Service for UI)

## Wire format (probe layer)

Each event from the BPF ringbuf is a 56-byte header + per-type body. Header layout:

| Field | Type | Bytes | Notes |
|---|---|---|---|
| `ts_ns` | u64 | 0..8 | `bpf_ktime_get_ns()` monotonic |
| `cgroup_id` | u64 | 8..16 | `bpf_get_current_cgroup_id()`; 0 if no cgroup v2 |
| `pid` | u32 | 16..20 | thread group id |
| `ppid` | u32 | 20..24 | parent tgid |
| `uid` | u32 | 24..28 | real uid |
| `gid` | u32 | 28..32 | real gid |
| `event_type` | u32 | 32..36 | discriminator |
| `comm` | char[16] | 36..52 | from `bpf_get_current_comm` |
| (pad) | — | 52..56 | trailing alignment |

Every typed body starts with `int64 ret` at offset 56 — the matching `sys_exit_*` syscall return value (0 success, negative `-errno`). Consumers type-switch on the channel:

```go
for ev := range eventCh {
    switch e := ev.(type) {
    case *probe.ConnectEvent:
        // e.Header().PID, e.DstIP, e.DstPort, e.Ret
    case *probe.OpenEvent:
        // e.Header().CgroupID, e.Path, e.Flags, e.Ret
    // ... 11 more typed events
    }
}
```

## License

Apache 2.0. See LICENSE.
