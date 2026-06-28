# vakta

Linux syscall observability agent. Kernel-side eBPF tracepoints emit structured events; userspace Go code consumes them via a ring buffer.

## Status

Early development. The probe layer (this repo's `internal/probe/`) emits typed events for execve, connect, openat, clone, ptrace, bpf, mmap and friends. No rule eval / alerting / storage yet.

## Requirements

- Linux kernel ≥ 5.8 with `CONFIG_DEBUG_INFO_BTF=y` (check `/sys/kernel/btf/vmlinux` exists)
- Go ≥ 1.25
- clang/LLVM ≥ 14
- `bpftool` (only needed to refresh `vmlinux.h`; ship with the repo for normal builds)

Install on Ubuntu 22.04+:
```bash
sudo apt-get install -y clang llvm libelf-dev linux-tools-common linux-tools-$(uname -r)
```

## Build

```bash
go generate ./internal/probe/...   # runs bpf2go to compile probe.bpf.c
go build ./...
```

## Test

Unit tests (no privileges):
```bash
go test ./...
```

Integration test (loads BPF, attaches tracepoints, requires root):
```bash
sudo -E go test -tags=integration -count=1 ./internal/probe/
```

## Wire format

Each event on the ring buffer begins with a 56-byte common header:

| Field | Type | Bytes | Notes |
|---|---|---|---|
| `ts_ns` | u64 | 0..8 | `bpf_ktime_get_ns()` monotonic |
| `cgroup_id` | u64 | 8..16 | `bpf_get_current_cgroup_id()`; 0 if no cgroup v2 |
| `pid` | u32 | 16..20 | thread group id (the "process id" most tools mean) |
| `ppid` | u32 | 20..24 | parent tgid |
| `uid` | u32 | 24..28 | real uid |
| `gid` | u32 | 28..32 | real gid |
| `event_type` | u32 | 32..36 | discriminator; see `EventType` constants in `internal/probe/types.go` |
| `comm` | char[16] | 36..52 | from `bpf_get_current_comm`; null-terminated unless >=15 chars |
| (pad) | — | 52..56 | trailing alignment pad |

Every typed event body then starts with `int64 ret` at offset 56 — the matching `sys_exit_*` syscall return value (0 on success, negative `-errno` on failure). Single-hook event types (`EXEC` via `sched_process_exec`, `MODULE_LOAD` via `do_init_module` kprobe) hard-code `ret = 0`.

The Go consumer side is in `internal/probe/types.go`: `EventHeader` + 13 typed `Event` implementations with `Ret int64` as the first body field. Use a type switch on the channel:

```go
for ev := range eventCh {
    switch e := ev.(type) {
    case *probe.ConnectEvent:
        // e.Header().PID, e.DstIP, e.DstPort, e.Ret
    case *probe.OpenEvent:
        // e.Header().CgroupID, e.Path, e.Flags, e.Ret
    // ... 11 more
    }
}
```

> **Wire-format compatibility:** the v0.2 wire format is incompatible with v0.1 (which had a 48-byte header and no `Ret` field). v0.1 was never released; v0.2.0 is the first published wire format.

## License

Apache 2.0. See LICENSE.
