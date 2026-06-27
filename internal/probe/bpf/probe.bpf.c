// SPDX-License-Identifier: Apache-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* -------------------- event enum (mirrored in Go types.go) -------------------- */
enum vakta_event_type {
    VK_EXEC_ATTEMPT = 1,
    VK_EXEC         = 2,
    VK_CONNECT      = 3,
    VK_OPEN         = 4,
    VK_CLONE        = 5,
    VK_UNSHARE      = 6,
    VK_PTRACE       = 7,
    VK_MODULE_LOAD  = 8,
    VK_BPF_LOAD     = 9,
    VK_MEMFD        = 10,
    VK_CHMOD        = 11,
    VK_MMAP_EXEC    = 12,
    VK_PROC_PROBE   = 13,
};

/* -------------------- common header (48 B on wire: 44 B fields + 4 B alignment pad) -------------------- */
struct vakta_hdr {
    __u64 ts_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 event_type;
    char  comm[16];
};

/* -------------------- per-type bodies (header + extras) -------------------- */
#define ARGV_MAX 128
struct exec_event {
    struct vakta_hdr hdr;
    __u32 argv_len;
    char  argv[ARGV_MAX];
};

/* -------------------- maps -------------------- */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drops SEC(".maps");

/* -------------------- helpers -------------------- */
static __always_inline void incr_drop(void) {
    __u32 zero = 0;
    __u64 *cnt = bpf_map_lookup_elem(&drops, &zero);
    if (cnt) __sync_fetch_and_add(cnt, 1);
}

static __always_inline void fill_hdr(struct vakta_hdr *h, __u32 type) {
    __u64 id = bpf_get_current_pid_tgid();
    h->ts_ns = bpf_ktime_get_ns();
    h->pid   = (__u32)(id >> 32);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    h->ppid  = BPF_CORE_READ(task, real_parent, tgid);
    __u64 uidgid = bpf_get_current_uid_gid();
    h->uid   = (__u32)uidgid;
    h->gid   = (__u32)(uidgid >> 32);
    h->event_type = type;
    bpf_get_current_comm(&h->comm, sizeof(h->comm));
}

/* -------------------- program: sched_process_exec → EXEC (with argv) -------------------- */
SEC("tracepoint/sched/sched_process_exec")
int handle_sched_exec(void *ctx) {
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_EXEC);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) {
        e->argv_len = 0;
        bpf_ringbuf_submit(e, 0);
        return 0;
    }
    unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
    unsigned long arg_end   = BPF_CORE_READ(mm, arg_end);
    unsigned long len = arg_end - arg_start;
    if (len > ARGV_MAX) len = ARGV_MAX;
    /* mask to make verifier happy about the bounded write */
    bpf_probe_read_user(&e->argv[0], len & (ARGV_MAX - 1), (void *)arg_start);
    e->argv_len = len;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
