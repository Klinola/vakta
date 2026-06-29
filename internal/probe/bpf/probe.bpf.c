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
    VK_PROC_MEM_OPEN = 14,
};

/* -------------------- common header (56 B on wire: 52 B fields + 4 B alignment pad) -------------------- */
struct vakta_hdr {
    __u64 ts_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 event_type;
    char  comm[16];
};

/* -------------------- per-type bodies (header + ret + extras) -------------------- */
#define ARGV_MAX 128
struct exec_event {
    struct vakta_hdr hdr;
    __s64 ret;             /* ret=0; sched_process_exec only fires on success */
    __u32 argv_len;
    char  argv[ARGV_MAX];
};

#define FILENAME_MAX_LEN 128
struct exec_attempt_event {
    struct vakta_hdr hdr;
    __s64 ret;
    char filename[FILENAME_MAX_LEN];
};

struct connect_event {
    struct vakta_hdr hdr;
    __s64 ret;
    __u16 family;
    __u16 dport;
    __u8  addr[16];      /* zero-padded; v4 uses first 4 bytes */
};

#define PATH_MAX_LEN 256
struct open_event {
    struct vakta_hdr hdr;
    __s64 ret;
    __s32 flags;
    char  path[PATH_MAX_LEN];
};

struct clone_event {
    struct vakta_hdr hdr;
    __s64 ret;
    __u64 clone_flags;
};

struct unshare_event {
    struct vakta_hdr hdr;
    __s64 ret;
    __u64 unshare_flags;
};

struct ptrace_event {
    struct vakta_hdr hdr;
    __s64 ret;
    __s64 request;
    __u32 target_pid;
};

#define MOD_NAME_MAX 64
struct module_load_event {
    struct vakta_hdr hdr;
    __s64 ret;   /* placeholder, ret stays 0 — kprobe has no sys_exit pair */
    char  name[MOD_NAME_MAX];
};

#define BPF_PROG_LOAD 5
struct bpf_load_event {
    struct vakta_hdr hdr;
    __s64 ret;
    __u32 prog_type;
};

#define MEMFD_NAME_MAX 64
struct memfd_event {
    struct vakta_hdr hdr;
    __s64 ret;
    __u32 flags;
    char  name[MEMFD_NAME_MAX];
};

struct chmod_event {
    struct vakta_hdr hdr;
    __s64 ret;
    __u32 mode;
    char  path[PATH_MAX_LEN];
};

#define PROT_WRITE_BIT 0x2
#define PROT_EXEC_BIT  0x4
struct mmap_exec_event {
    struct vakta_hdr hdr;
    __s64 ret;
    __u64 addr;
    __u64 len;
    __u32 prot;
};

struct proc_probe_event {
    struct vakta_hdr hdr;
    __s64 ret;
    __u32 target_pid;
};

/* 56(hdr) + 8(ret) + 4(target_pid) + 4(target_uid) = 72 B; well under PENDING_RAW_MAX */
struct proc_mem_open_event {
    struct vakta_hdr hdr;
    __s64  ret;
    __u32  target_pid;
    __u32  target_uid; /* filled by Go normalizer via /proc/<pid>/status; 0 here */
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

/* sys_enter handlers stash a partial event here; the paired sys_exit pops it,
 * copies to ringbuf, sets ret = ctx->ret, submits, and deletes. */
#define PENDING_MAX 16384
/* MUST be a power of two: store_pending / emit_paired mask body_size with
 * (PENDING_RAW_MAX - 1) to convince the verifier the memcpy size is bounded.
 * 512 is the smallest power of two ≥ the largest per-type body (open/chmod
 * ≈ 328 B). */
#define PENDING_RAW_MAX 512
_Static_assert((PENDING_RAW_MAX & (PENDING_RAW_MAX - 1)) == 0,
               "PENDING_RAW_MAX must be a power of two (see store_pending mask)");

struct pending_event {
    __u32 event_type;
    __u32 _pad;
    char  raw[PENDING_RAW_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, PENDING_MAX);
    __type(key, __u64);
    __type(value, struct pending_event);
} pending SEC(".maps");

/* Per-CPU scratch for building a pending_event without blowing the 512 B BPF
 * stack limit. Each enter handler runs to completion before the same CPU runs
 * another handler, so a single slot per CPU is safe. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pending_event);
} pending_scratch SEC(".maps");

/* -------------------- helpers -------------------- */
static __always_inline void incr_drop(void) {
    __u32 zero = 0;
    __u64 *cnt = bpf_map_lookup_elem(&drops, &zero);
    if (cnt) __sync_fetch_and_add(cnt, 1);
}

static __always_inline void fill_hdr(struct vakta_hdr *h, __u32 type) {
    __u64 id = bpf_get_current_pid_tgid();
    h->ts_ns     = bpf_ktime_get_ns();
    h->cgroup_id = bpf_get_current_cgroup_id();
    h->pid       = (__u32)(id >> 32);
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    h->ppid      = BPF_CORE_READ(task, real_parent, tgid);
    __u64 uidgid = bpf_get_current_uid_gid();
    h->uid       = (__u32)uidgid;
    h->gid       = (__u32)(uidgid >> 32);
    h->event_type = type;
    bpf_get_current_comm(&h->comm, sizeof(h->comm));
}

static __always_inline void store_pending(__u32 event_type, void *body, __u32 body_size) {
    if (body_size > PENDING_RAW_MAX) { incr_drop(); return; }
    __u32 zero = 0;
    struct pending_event *p = bpf_map_lookup_elem(&pending_scratch, &zero);
    if (!p) { incr_drop(); return; }
    p->event_type = event_type;
    p->_pad = 0;
    __u32 sz = body_size & (PENDING_RAW_MAX - 1);
    if (sz != body_size) { incr_drop(); return; }
    __builtin_memcpy(p->raw, body, sz);
    __u64 key = bpf_get_current_pid_tgid();
    if (bpf_map_update_elem(&pending, &key, p, BPF_ANY) != 0) { incr_drop(); return; }
}

/* Returns 1 when a pending entry matched + was emitted, 0 otherwise.
 * sys_exit dispatcher (issue #1) uses the return value for openat's
 * PROC_MEM_OPEN-then-OPEN fallthrough. Tracing program return value is
 * ignored by the kernel either way, so existing callers staying `return
 * emit_paired(...)` are unaffected. */
static __always_inline int emit_paired(__u32 expected_type, __s64 ret, __u32 body_size) {
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_event *p = bpf_map_lookup_elem(&pending, &key);
    if (!p || p->event_type != expected_type) return 0;

    void *dst = bpf_ringbuf_reserve(&events, body_size, 0);
    if (!dst) { bpf_map_delete_elem(&pending, &key); incr_drop(); return 0; }

    __u32 sz = body_size & (PENDING_RAW_MAX - 1);
    if (sz != body_size) {
        bpf_ringbuf_discard(dst, 0);
        bpf_map_delete_elem(&pending, &key);
        return 0;
    }
    __builtin_memcpy(dst, p->raw, sz);
    /* ret lives at offset sizeof(vakta_hdr) = 56 in every per-type struct */
    *((__s64 *)((char *)dst + sizeof(struct vakta_hdr))) = ret;

    bpf_ringbuf_submit(dst, 0);
    bpf_map_delete_elem(&pending, &key);
    return 1;
}

/* -------------------- program: sched_process_exec → EXEC (with argv, single-hook) -------------------- */
SEC("tracepoint/sched/sched_process_exec")
int handle_sched_exec(void *ctx) {
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_EXEC);
    e->ret = 0;

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
    if (len > ARGV_MAX - 1) len = ARGV_MAX - 1;
    /* mask to make verifier happy about the bounded write */
    bpf_probe_read_user(&e->argv[0], len & (ARGV_MAX - 1), (void *)arg_start);
    e->argv_len = len;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* -------------------- helpers: exec_attempt, open, proc_mem_pid -------------------- */
static __always_inline int do_exec_attempt(const char *filename) {
    struct exec_attempt_event e = {};
    fill_hdr(&e.hdr, VK_EXEC_ATTEMPT);
    bpf_probe_read_user_str(&e.filename, sizeof(e.filename), filename);
    store_pending(VK_EXEC_ATTEMPT, &e, sizeof(e));
    return 0;
}

static __always_inline int do_open(const char *path, __s32 flags) {
    struct open_event e = {};
    fill_hdr(&e.hdr, VK_OPEN);
    e.flags = flags;
    bpf_probe_read_user_str(&e.path, sizeof(e.path), path);
    store_pending(VK_OPEN, &e, sizeof(e));
    return 0;
}

/* Fires when a process opens /proc/<other-pid>/mem (T1055 injection vector).
 * target_uid is set to 0 here; the Go normalizer fills it from /proc/<pid>/status
 * because bpf_task_from_pid() requires kernel 5.15 but vakta requires only 5.8. */
static __always_inline __u32 parse_proc_mem_pid(const char *upath) {
    char buf[32];
    long n = bpf_probe_read_user_str(buf, sizeof(buf), upath);
    if (n <= 0) return 0;
    if (buf[0] != '/' || buf[1] != 'p' || buf[2] != 'r' ||
        buf[3] != 'o' || buf[4] != 'c' || buf[5] != '/') return 0;
    __u32 pid = 0;
    int i;
    #pragma unroll
    for (i = 6; i < 22; i++) {
        char c = buf[i];
        if (c >= '0' && c <= '9') { pid = pid * 10 + (c - '0'); continue; }
        if (c == '/') break;
        return 0;
    }
    if (pid == 0 || i >= 28) return 0;
    if (buf[i] != '/' || buf[i+1] != 'm' || buf[i+2] != 'e' || buf[i+3] != 'n') return 0;
    return pid;
}

/* -------------------- tp_btf full dispatcher (issue #1) --------------------
 * tp_btf attaches via LinkCreateTracing / bpf_raw_tracepoint_open, bypassing
 * perf_event_set_bpf_prog (the path that returns EACCES on Rocky/RHEL 9.x).
 * BPF_PROG(name, args...) unpacks ctx->args[i] as typed C pointers via BTF.
 * x86_64 syscall NRs only — single-arch like the original POC. */

#define VAKTA_NR_execve        59
#define VAKTA_NR_execveat     322
#define VAKTA_NR_connect       42
#define VAKTA_NR_openat       257
#define VAKTA_NR_open           2
#define VAKTA_NR_clone         56
#define VAKTA_NR_clone3       435
#define VAKTA_NR_unshare      272
#define VAKTA_NR_ptrace       101
#define VAKTA_NR_bpf          321
#define VAKTA_NR_memfd_create 319
#define VAKTA_NR_chmod         90
#define VAKTA_NR_fchmod        91
#define VAKTA_NR_fchmodat     268
#define VAKTA_NR_mmap           9
#define VAKTA_NR_kill          62

SEC("tp_btf/sys_enter")
int BPF_PROG(handle_raw_sys_enter, struct pt_regs *regs, long id) {
    switch (id) {

    case VAKTA_NR_execve:
        return do_exec_attempt((const char *)PT_REGS_PARM1_SYSCALL(regs));

    case VAKTA_NR_execveat:
        /* args: dfd, filename, argv, envp, flags */
        return do_exec_attempt((const char *)PT_REGS_PARM2_SYSCALL(regs));

    case VAKTA_NR_connect: {
        const struct sockaddr *uservaddr =
            (const struct sockaddr *)PT_REGS_PARM2_SYSCALL(regs);
        if (!uservaddr) return 0;
        __u16 family = 0;
        bpf_probe_read_user(&family, sizeof(family), uservaddr);
        struct connect_event e = {};
        fill_hdr(&e.hdr, VK_CONNECT);
        e.family = family;
        if (family == 2 /* AF_INET */) {
            struct sockaddr_in s4 = {};
            bpf_probe_read_user(&s4, sizeof(s4), uservaddr);
            e.dport = bpf_ntohs(s4.sin_port);
            __builtin_memcpy(&e.addr[0], &s4.sin_addr, 4);
        } else if (family == 10 /* AF_INET6 */) {
            struct sockaddr_in6 s6 = {};
            bpf_probe_read_user(&s6, sizeof(s6), uservaddr);
            e.dport = bpf_ntohs(s6.sin6_port);
            __builtin_memcpy(&e.addr[0], &s6.sin6_addr, 16);
        }
        store_pending(VK_CONNECT, &e, sizeof(e));
        break;
    }

    case VAKTA_NR_openat: {
        /* args: dfd, filename, flags, mode */
        const char *path = (const char *)PT_REGS_PARM2_SYSCALL(regs);
        __s32 flags      = (__s32)PT_REGS_PARM3_SYSCALL(regs);

        /* OPEN pending — paired with sys_exit case below */
        do_open(path, flags);

        /* proc_mem detection: emit immediately to ringbuf (not via pending map)
         * because the pending slot is already taken by OPEN above.
         * Behavior change vs old code: VK_PROC_MEM_OPEN ret field is always 0
         * (Go normalizer fills target_uid via /proc/<pid>/status as before). */
        __u32 target_pid = parse_proc_mem_pid(path);
        if (target_pid != 0) {
            __u32 my_pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
            if (target_pid != my_pid) {
                struct proc_mem_open_event *pm =
                    bpf_ringbuf_reserve(&events, sizeof(*pm), 0);
                if (pm) {
                    fill_hdr(&pm->hdr, VK_PROC_MEM_OPEN);
                    pm->ret        = 0;
                    pm->target_pid = target_pid;
                    pm->target_uid = 0;
                    bpf_ringbuf_submit(pm, 0);
                } else {
                    incr_drop();
                }
            }
        }
        break;
    }

    case VAKTA_NR_open:
        /* args: filename, flags, mode */
        return do_open((const char *)PT_REGS_PARM1_SYSCALL(regs),
                       (__s32)PT_REGS_PARM2_SYSCALL(regs));

    case VAKTA_NR_clone: {
        struct clone_event e = {};
        fill_hdr(&e.hdr, VK_CLONE);
        e.clone_flags = (__u64)PT_REGS_PARM1_SYSCALL(regs);
        store_pending(VK_CLONE, &e, sizeof(e));
        break;
    }

    case VAKTA_NR_clone3: {
        /* args: cl_args*, size */
        struct clone_args ca = {};
        bpf_probe_read_user(&ca, sizeof(ca),
                            (void *)PT_REGS_PARM1_SYSCALL(regs));
        struct clone_event e = {};
        fill_hdr(&e.hdr, VK_CLONE);
        e.clone_flags = ca.flags;
        store_pending(VK_CLONE, &e, sizeof(e));
        break;
    }

    case VAKTA_NR_unshare: {
        struct unshare_event e = {};
        fill_hdr(&e.hdr, VK_UNSHARE);
        e.unshare_flags = (__u64)PT_REGS_PARM1_SYSCALL(regs);
        store_pending(VK_UNSHARE, &e, sizeof(e));
        break;
    }

    case VAKTA_NR_ptrace: {
        struct ptrace_event e = {};
        fill_hdr(&e.hdr, VK_PTRACE);
        e.request    = (__s64)PT_REGS_PARM1_SYSCALL(regs);
        e.target_pid = (__u32)PT_REGS_PARM2_SYSCALL(regs);
        store_pending(VK_PTRACE, &e, sizeof(e));
        break;
    }

    case VAKTA_NR_bpf: {
        int cmd = (int)PT_REGS_PARM1_SYSCALL(regs);
        if (cmd != BPF_PROG_LOAD) return 0;
        union bpf_attr attr = {};
        bpf_probe_read_user(&attr, sizeof(attr),
                            (void *)PT_REGS_PARM2_SYSCALL(regs));
        struct bpf_load_event e = {};
        fill_hdr(&e.hdr, VK_BPF_LOAD);
        e.prog_type = attr.prog_type;
        store_pending(VK_BPF_LOAD, &e, sizeof(e));
        break;
    }

    case VAKTA_NR_memfd_create: {
        struct memfd_event e = {};
        fill_hdr(&e.hdr, VK_MEMFD);
        e.flags = (__u32)PT_REGS_PARM2_SYSCALL(regs);
        bpf_probe_read_user_str(&e.name, sizeof(e.name),
                                (const char *)PT_REGS_PARM1_SYSCALL(regs));
        store_pending(VK_MEMFD, &e, sizeof(e));
        break;
    }

    case VAKTA_NR_chmod: {
        struct chmod_event e = {};
        fill_hdr(&e.hdr, VK_CHMOD);
        e.mode = (__u32)PT_REGS_PARM2_SYSCALL(regs);
        bpf_probe_read_user_str(&e.path, sizeof(e.path),
                                (const char *)PT_REGS_PARM1_SYSCALL(regs));
        store_pending(VK_CHMOD, &e, sizeof(e));
        break;
    }

    case VAKTA_NR_fchmod: {
        /* args: fd, mode — no path */
        struct chmod_event e = {};
        fill_hdr(&e.hdr, VK_CHMOD);
        e.mode    = (__u32)PT_REGS_PARM2_SYSCALL(regs);
        e.path[0] = 0;
        store_pending(VK_CHMOD, &e, sizeof(e));
        break;
    }

    case VAKTA_NR_fchmodat: {
        /* args: dfd, path, mode */
        struct chmod_event e = {};
        fill_hdr(&e.hdr, VK_CHMOD);
        e.mode = (__u32)PT_REGS_PARM3_SYSCALL(regs);
        bpf_probe_read_user_str(&e.path, sizeof(e.path),
                                (const char *)PT_REGS_PARM2_SYSCALL(regs));
        store_pending(VK_CHMOD, &e, sizeof(e));
        break;
    }

    case VAKTA_NR_mmap: {
        __u32 prot = (__u32)PT_REGS_PARM3_SYSCALL(regs);
        if (!(prot & PROT_WRITE_BIT) || !(prot & PROT_EXEC_BIT)) return 0;
        struct mmap_exec_event e = {};
        fill_hdr(&e.hdr, VK_MMAP_EXEC);
        e.addr = (__u64)PT_REGS_PARM1_SYSCALL(regs);
        e.len  = (__u64)PT_REGS_PARM2_SYSCALL(regs);
        e.prot = prot;
        store_pending(VK_MMAP_EXEC, &e, sizeof(e));
        break;
    }

    case VAKTA_NR_kill: {
        int sig = (int)PT_REGS_PARM2_SYSCALL(regs);
        if (sig != 0) return 0;
        struct proc_probe_event e = {};
        fill_hdr(&e.hdr, VK_PROC_PROBE);
        e.target_pid = (__u32)PT_REGS_PARM1_SYSCALL(regs);
        store_pending(VK_PROC_PROBE, &e, sizeof(e));
        break;
    }

    }
    return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(handle_raw_sys_exit, struct pt_regs *regs, long ret) {
    long id = (long)BPF_CORE_READ(regs, orig_ax);
    switch (id) {
    case VAKTA_NR_execve:
    case VAKTA_NR_execveat:
        return emit_paired(VK_EXEC_ATTEMPT, (__s64)ret, sizeof(struct exec_attempt_event));
    case VAKTA_NR_connect:
        return emit_paired(VK_CONNECT, (__s64)ret, sizeof(struct connect_event));
    case VAKTA_NR_openat:
    case VAKTA_NR_open:
        return emit_paired(VK_OPEN, (__s64)ret, sizeof(struct open_event));
    case VAKTA_NR_clone:
    case VAKTA_NR_clone3:
        return emit_paired(VK_CLONE, (__s64)ret, sizeof(struct clone_event));
    case VAKTA_NR_unshare:
        return emit_paired(VK_UNSHARE, (__s64)ret, sizeof(struct unshare_event));
    case VAKTA_NR_ptrace:
        return emit_paired(VK_PTRACE, (__s64)ret, sizeof(struct ptrace_event));
    case VAKTA_NR_bpf:
        return emit_paired(VK_BPF_LOAD, (__s64)ret, sizeof(struct bpf_load_event));
    case VAKTA_NR_memfd_create:
        return emit_paired(VK_MEMFD, (__s64)ret, sizeof(struct memfd_event));
    case VAKTA_NR_chmod:
    case VAKTA_NR_fchmod:
    case VAKTA_NR_fchmodat:
        return emit_paired(VK_CHMOD, (__s64)ret, sizeof(struct chmod_event));
    case VAKTA_NR_mmap:
        return emit_paired(VK_MMAP_EXEC, (__s64)ret, sizeof(struct mmap_exec_event));
    case VAKTA_NR_kill:
        return emit_paired(VK_PROC_PROBE, (__s64)ret, sizeof(struct proc_probe_event));
    }
    return 0;
}

/* -------------------- program: do_init_module → MODULE_LOAD (kprobe, single-hook) -------------------- */
SEC("kprobe/do_init_module")
int BPF_KPROBE(handle_do_init_module, struct module *mod) {
    struct module_load_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { incr_drop(); return 0; }
    fill_hdr(&e->hdr, VK_MODULE_LOAD);
    e->ret = 0;
    bpf_probe_read_kernel_str(&e->name, sizeof(e->name), BPF_CORE_READ(mod, name));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

