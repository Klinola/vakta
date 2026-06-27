// SPDX-License-Identifier: Apache-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

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

#define FILENAME_MAX_LEN 128
struct exec_attempt_event {
    struct vakta_hdr hdr;
    char filename[FILENAME_MAX_LEN];
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

/* -------------------- program: sys_enter_execve/execveat → EXEC_ATTEMPT -------------------- */
static __always_inline int do_exec_attempt(const char *filename) {
    struct exec_attempt_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_EXEC_ATTEMPT);
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    return do_exec_attempt((const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_sys_enter_execveat(struct trace_event_raw_sys_enter *ctx) {
    /* args: dfd, filename, argv, envp, flags */
    return do_exec_attempt((const char *)ctx->args[1]);
}

/* -------------------- program: sys_enter_connect → CONNECT -------------------- */
struct connect_event {
    struct vakta_hdr hdr;
    __u16 family;
    __u16 dport;
    __u8  addr[16];      /* zero-padded; v4 uses first 4 bytes */
};

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    const struct sockaddr *uservaddr = (const struct sockaddr *)ctx->args[1];
    if (!uservaddr) return 0;

    /* Read family first */
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), uservaddr);

    struct connect_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_CONNECT);
    e->family = family;
    __builtin_memset(e->addr, 0, sizeof(e->addr));

    if (family == 2 /* AF_INET */) {
        struct sockaddr_in s4 = {};
        bpf_probe_read_user(&s4, sizeof(s4), uservaddr);
        e->dport = bpf_ntohs(s4.sin_port);
        __builtin_memcpy(&e->addr[0], &s4.sin_addr, 4);
    } else if (family == 10 /* AF_INET6 */) {
        struct sockaddr_in6 s6 = {};
        bpf_probe_read_user(&s6, sizeof(s6), uservaddr);
        e->dport = bpf_ntohs(s6.sin6_port);
        __builtin_memcpy(&e->addr[0], &s6.sin6_addr, 16);
    } else {
        e->dport = 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* -------------------- program: sys_enter_openat/open → OPEN -------------------- */
#define PATH_MAX_LEN 256
struct open_event {
    struct vakta_hdr hdr;
    __s32 flags;
    char  path[PATH_MAX_LEN];
};

static __always_inline int do_open(const char *path, __s32 flags) {
    struct open_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_OPEN);
    e->flags = flags;
    bpf_probe_read_user_str(&e->path, sizeof(e->path), path);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    /* args: dfd, filename, flags, mode */
    return do_open((const char *)ctx->args[1], (__s32)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_open")
int handle_sys_enter_open(struct trace_event_raw_sys_enter *ctx) {
    /* args: filename, flags, mode */
    return do_open((const char *)ctx->args[0], (__s32)ctx->args[1]);
}

/* -------------------- program: sys_enter_clone/clone3 → CLONE -------------------- */
struct clone_event {
    struct vakta_hdr hdr;
    __u64 clone_flags;
};

SEC("tracepoint/syscalls/sys_enter_clone")
int handle_sys_enter_clone(struct trace_event_raw_sys_enter *ctx) {
    struct clone_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_CLONE);
    e->clone_flags = (__u64)ctx->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone3")
int handle_sys_enter_clone3(struct trace_event_raw_sys_enter *ctx) {
    /* args: cl_args, size */
    struct clone_args ca = {};
    bpf_probe_read_user(&ca, sizeof(ca), (void *)ctx->args[0]);
    struct clone_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_CLONE);
    e->clone_flags = ca.flags;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* -------------------- program: sys_enter_unshare → UNSHARE -------------------- */
struct unshare_event {
    struct vakta_hdr hdr;
    __u64 unshare_flags;
};

SEC("tracepoint/syscalls/sys_enter_unshare")
int handle_sys_enter_unshare(struct trace_event_raw_sys_enter *ctx) {
    struct unshare_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_UNSHARE);
    e->unshare_flags = (__u64)ctx->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* -------------------- program: sys_enter_ptrace → PTRACE -------------------- */
struct ptrace_event {
    struct vakta_hdr hdr;
    __s64 request;
    __u32 target_pid;
};

SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_sys_enter_ptrace(struct trace_event_raw_sys_enter *ctx) {
    struct ptrace_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_PTRACE);
    e->request    = (__s64)ctx->args[0];
    e->target_pid = (__u32)ctx->args[1];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* -------------------- program: sys_enter_init_module/finit_module → MODULE_LOAD -------------------- */
#define MOD_NAME_MAX 64
struct module_load_event {
    struct vakta_hdr hdr;
    char name[MOD_NAME_MAX];
};

SEC("tracepoint/syscalls/sys_enter_init_module")
int handle_sys_enter_init_module(struct trace_event_raw_sys_enter *ctx) {
    struct module_load_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_MODULE_LOAD);
    e->name[0] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int handle_sys_enter_finit_module(struct trace_event_raw_sys_enter *ctx) {
    struct module_load_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_MODULE_LOAD);
    e->name[0] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* -------------------- program: sys_enter_bpf → BPF_LOAD -------------------- */
#define BPF_PROG_LOAD 5
struct bpf_load_event {
    struct vakta_hdr hdr;
    __u32 prog_type;
};

SEC("tracepoint/syscalls/sys_enter_bpf")
int handle_sys_enter_bpf(struct trace_event_raw_sys_enter *ctx) {
    int cmd = (int)ctx->args[0];
    if (cmd != BPF_PROG_LOAD) return 0;

    union bpf_attr attr = {};
    bpf_probe_read_user(&attr, sizeof(attr), (void *)ctx->args[1]);

    struct bpf_load_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_BPF_LOAD);
    e->prog_type = attr.prog_type;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* -------------------- program: sys_enter_memfd_create → MEMFD -------------------- */
#define MEMFD_NAME_MAX 64
struct memfd_event {
    struct vakta_hdr hdr;
    __u32 flags;
    char  name[MEMFD_NAME_MAX];
};

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int handle_sys_enter_memfd_create(struct trace_event_raw_sys_enter *ctx) {
    struct memfd_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_MEMFD);
    e->flags = (__u32)ctx->args[1];
    bpf_probe_read_user_str(&e->name, sizeof(e->name), (const char *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* -------------------- program: sys_enter_chmod/fchmod/fchmodat → CHMOD -------------------- */
struct chmod_event {
    struct vakta_hdr hdr;
    __u32 mode;
    char  path[PATH_MAX_LEN];
};

SEC("tracepoint/syscalls/sys_enter_chmod")
int handle_sys_enter_chmod(struct trace_event_raw_sys_enter *ctx) {
    struct chmod_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_CHMOD);
    e->mode = (__u32)ctx->args[1];
    bpf_probe_read_user_str(&e->path, sizeof(e->path), (const char *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int handle_sys_enter_fchmod(struct trace_event_raw_sys_enter *ctx) {
    struct chmod_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_CHMOD);
    e->mode = (__u32)ctx->args[1];
    e->path[0] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int handle_sys_enter_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    struct chmod_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_CHMOD);
    e->mode = (__u32)ctx->args[2];
    bpf_probe_read_user_str(&e->path, sizeof(e->path), (const char *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* -------------------- program: sys_enter_mmap → MMAP_EXEC (PROT_EXEC|PROT_WRITE) -------------------- */
#define PROT_WRITE_BIT 0x2
#define PROT_EXEC_BIT  0x4
struct mmap_exec_event {
    struct vakta_hdr hdr;
    __u64 addr;
    __u64 len;
    __u32 prot;
};

SEC("tracepoint/syscalls/sys_enter_mmap")
int handle_sys_enter_mmap(struct trace_event_raw_sys_enter *ctx) {
    __u32 prot = (__u32)ctx->args[2];
    if (!(prot & PROT_WRITE_BIT) || !(prot & PROT_EXEC_BIT)) return 0;
    struct mmap_exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_MMAP_EXEC);
    e->addr = (__u64)ctx->args[0];
    e->len  = (__u64)ctx->args[1];
    e->prot = prot;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* -------------------- program: sys_enter_kill → PROC_PROBE (sig=0) -------------------- */
struct proc_probe_event {
    struct vakta_hdr hdr;
    __u32 target_pid;
};

SEC("tracepoint/syscalls/sys_enter_kill")
int handle_sys_enter_kill(struct trace_event_raw_sys_enter *ctx) {
    int sig = (int)ctx->args[1];
    if (sig != 0) return 0;
    struct proc_probe_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_PROC_PROBE);
    e->target_pid = (__u32)ctx->args[0];
    bpf_ringbuf_submit(e, 0);
    return 0;
}
