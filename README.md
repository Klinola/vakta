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

## License

Apache 2.0. See LICENSE.
