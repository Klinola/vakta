// SPDX-License-Identifier: Apache-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Placeholder map and program so bpf2go produces a non-empty object.
// Replaced in Task 4.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int handle_stub(void *ctx) { return 0; }
