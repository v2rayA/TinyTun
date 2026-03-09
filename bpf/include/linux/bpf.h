/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Self-contained linux/bpf.h for TinyTun BPF programs.
 *
 * This file is found first by clang (bpf/include/ is the first -I path) and
 * REPLACES the system-installed header entirely, so no specific version of
 * linux-libc-dev is required for the BPF definitions.
 *
 * Why not use #include_next?  Cross-compilation containers (e.g. the cross-rs
 * armv7-unknown-linux-gnueabihf image) pre-install ARM-specific kernel
 * headers that can be as old as Linux 4.4.  That version is missing:
 *   - BPF_MAP_TYPE_LPM_TRIE (Linux 4.11)
 *   - BPF_F_NO_PREALLOC     (Linux 4.6)
 *   - BPF_MAP_TYPE_SOCKMAP  (Linux 4.14)
 *   - __sk_buff.data / .data_end (Linux 4.7)
 *   - SK_PASS / sk_action   (Linux 4.13)
 *   - struct bpf_sk_lookup  (Linux 5.9)
 * Patching on top of such an old header is fragile; providing a complete
 * standalone version is simpler and more reliable.
 *
 * Struct layouts are taken verbatim from Linux 5.15 UAPI.  TinyTun requires
 * a kernel that supports BPF_PROG_TYPE_SK_LOOKUP (Linux 5.9+), so these
 * layouts are appropriate.  The BPF verifier validates all field accesses at
 * load time against the running kernel's own internal definitions.
 *
 * Only the types and constants actually used by bpf/tinytun.bpf.c and the
 * vendored bpf/include/bpf/bpf_helper_defs.h are defined here.
 */

#ifndef __TINYTUN_LINUX_BPF_H
#define __TINYTUN_LINUX_BPF_H

/*
 * Pull in basic integer types (__u8, __u16, __u32, __u64, __be16, __s32 …).
 * linux/types.h is universally available even on very old linux-libc-dev
 * versions, and is the only system header we depend on here.
 */
#include <linux/types.h>

/* =========================================================================
 * BPF map types
 * ========================================================================= */

enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH,
    BPF_MAP_TYPE_ARRAY,
    BPF_MAP_TYPE_PROG_ARRAY,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    BPF_MAP_TYPE_PERCPU_HASH,
    BPF_MAP_TYPE_PERCPU_ARRAY,
    BPF_MAP_TYPE_STACK_TRACE,
    BPF_MAP_TYPE_CGROUP_ARRAY,
    BPF_MAP_TYPE_LRU_HASH,
    BPF_MAP_TYPE_LRU_PERCPU_HASH,
    BPF_MAP_TYPE_LPM_TRIE,          /* Linux 4.11 */
    BPF_MAP_TYPE_ARRAY_OF_MAPS,
    BPF_MAP_TYPE_HASH_OF_MAPS,
    BPF_MAP_TYPE_DEVMAP,
    BPF_MAP_TYPE_SOCKMAP,           /* Linux 4.14 */
    BPF_MAP_TYPE_CPUMAP,
    BPF_MAP_TYPE_XSKMAP,
    BPF_MAP_TYPE_SOCKHASH,
    BPF_MAP_TYPE_CGROUP_STORAGE,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
    BPF_MAP_TYPE_QUEUE,
    BPF_MAP_TYPE_STACK,
    BPF_MAP_TYPE_SK_STORAGE,
    BPF_MAP_TYPE_DEVMAP_HASH,
    BPF_MAP_TYPE_STRUCT_OPS,
    BPF_MAP_TYPE_RINGBUF,
    BPF_MAP_TYPE_INODE_STORAGE,
    BPF_MAP_TYPE_TASK_STORAGE,
};

/* ---- Map-creation flags ------------------------------------------------- */
#define BPF_F_NO_PREALLOC   (1U << 0)   /* Linux 4.6 */
#define BPF_F_NO_COMMON_LRU (1U << 1)
#define BPF_F_NUMA_NODE     (1U << 2)
#define BPF_F_RDONLY        (1U << 3)
#define BPF_F_WRONLY        (1U << 4)
#define BPF_F_STACK_BUILD_ID (1U << 5)
#define BPF_F_ZERO_SEED     (1U << 6)
#define BPF_F_RDONLY_PROG   (1U << 7)
#define BPF_F_WRONLY_PROG   (1U << 8)
#define BPF_F_CLONE         (1U << 9)
#define BPF_F_MMAPABLE      (1U << 10)
#define BPF_F_PRESERVE_ELEMS (1U << 11)
#define BPF_F_INNER_MAP     (1U << 12)

/* =========================================================================
 * BPF program types (subset – only what bpf_helper_defs.h needs)
 * ========================================================================= */

enum bpf_prog_type {
    BPF_PROG_TYPE_UNSPEC = 0,
    BPF_PROG_TYPE_SOCKET_FILTER,
    BPF_PROG_TYPE_KPROBE,
    BPF_PROG_TYPE_SCHED_CLS,
    BPF_PROG_TYPE_SCHED_ACT,
    BPF_PROG_TYPE_TRACEPOINT,
    BPF_PROG_TYPE_XDP,
    BPF_PROG_TYPE_PERF_EVENT,
    BPF_PROG_TYPE_CGROUP_SKB,
    BPF_PROG_TYPE_CGROUP_SOCK,
    BPF_PROG_TYPE_LWT_IN,
    BPF_PROG_TYPE_LWT_OUT,
    BPF_PROG_TYPE_LWT_XMIT,
    BPF_PROG_TYPE_SOCK_OPS,
    BPF_PROG_TYPE_SK_SKB,
    BPF_PROG_TYPE_CGROUP_DEVICE,
    BPF_PROG_TYPE_SK_MSG,
    BPF_PROG_TYPE_RAW_TRACEPOINT,
    BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
    BPF_PROG_TYPE_LWT_SEG6LOCAL,
    BPF_PROG_TYPE_LIRC_MODE2,
    BPF_PROG_TYPE_SK_REUSEPORT,
    BPF_PROG_TYPE_FLOW_DISSECTOR,
    BPF_PROG_TYPE_CGROUP_SYSCTL,
    BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
    BPF_PROG_TYPE_CGROUP_SOCKOPT,
    BPF_PROG_TYPE_TRACING,
    BPF_PROG_TYPE_STRUCT_OPS,
    BPF_PROG_TYPE_EXT,
    BPF_PROG_TYPE_LSM,
    BPF_PROG_TYPE_SK_LOOKUP,        /* Linux 5.9 */
};

/* =========================================================================
 * SK action (used by SOCKMAP / SK_LOOKUP programs)
 * Linux 4.13+
 * ========================================================================= */

enum sk_action {
    SK_DROP = 0,
    SK_PASS,
};

/* =========================================================================
 * BPF_FUNC_sk_assign flags (used with bpf_sk_assign helper)
 * ========================================================================= */

enum {
    BPF_SK_LOOKUP_F_REPLACE      = (1ULL << 0),
    BPF_SK_LOOKUP_F_NO_REUSEPORT = (1ULL << 1),
};

/* =========================================================================
 * Forward declarations required by bpf_helper_defs.h
 * ========================================================================= */

struct bpf_fib_lookup;
struct bpf_perf_event_data;
struct bpf_perf_event_value;
struct bpf_pidns_info;
struct bpf_redir_neigh;
struct bpf_sock_addr;
struct bpf_sock_ops;
struct bpf_sock_tuple;
struct bpf_spin_lock;
struct bpf_sysctl;
struct bpf_tcp_sock;
struct bpf_tunnel_key;
struct bpf_xfrm_state;
struct linux_binprm;
struct pt_regs;
struct sk_reuseport_md;
struct sockaddr;
struct tcphdr;
struct seq_file;
struct tcp6_sock;
struct tcp_sock;
struct tcp_timewait_sock;
struct tcp_request_sock;
struct udp6_sock;
struct unix_sock;
struct xdp_sock;
struct xdp_md;
struct sk_msg_md;
struct sk_skb_md;

/* =========================================================================
 * struct bpf_sock – minimal definition used by bpf_sk_lookup.sk
 * Layout: Linux 5.15 UAPI
 * ========================================================================= */

struct bpf_sock {
    __u32 bound_dev_if;
    __u32 family;
    __u32 type;
    __u32 protocol;
    __u32 mark;
    __u32 priority;
    __u32 src_ip4;
    __u32 src_ip6[4];
    __u32 src_port;         /* host byte order */
    __be16 dst_port;        /* network byte order */
    __u16 :16;
    __u32 dst_ip4;
    __u32 dst_ip6[4];
    __u32 state;
    __s32 rx_queue_mapping;
};

/* =========================================================================
 * struct __sk_buff – TC / socket program context
 *
 * Layout: Linux 5.15 UAPI (include/uapi/linux/bpf.h).
 * tinytun_tc_egress accesses: .data, .data_end, .mark
 * Field offsets must match exactly so the BPF verifier accepts them.
 * ========================================================================= */

struct __sk_buff {
    __u32 len;              /* offset   0 */
    __u32 pkt_type;         /* offset   4 */
    __u32 mark;             /* offset   8 */
    __u32 queue_mapping;    /* offset  12 */
    __u32 protocol;         /* offset  16 */
    __u32 vlan_present;     /* offset  20 */
    __u32 vlan_tci;         /* offset  24 */
    __u32 vlan_proto;       /* offset  28 */
    __u32 priority;         /* offset  32 */
    __u32 ingress_ifindex;  /* offset  36 */
    __u32 ifindex;          /* offset  40 */
    __u32 tc_index;         /* offset  44 */
    __u32 cb[5];            /* offset  48  (20 bytes) */
    __u32 hash;             /* offset  68 */
    __u32 tc_classid;       /* offset  72 */
    __u32 data;             /* offset  76  – Linux 4.7+ */
    __u32 data_end;         /* offset  80  – Linux 4.7+ */
    __u32 napi_id;          /* offset  84 */
    __u32 family;           /* offset  88 */
    __u32 remote_ip4;       /* offset  92 */
    __u32 local_ip4;        /* offset  96 */
    __u32 remote_ip6[4];    /* offset 100 */
    __u32 local_ip6[4];     /* offset 116 */
    __u32 remote_port;      /* offset 132 */
    __u32 local_port;       /* offset 136 */
    __u32 data_meta;        /* offset 140 */
    /* further fields omitted; tinytun only uses the above */
};

/* =========================================================================
 * struct bpf_sk_lookup – SK_LOOKUP program context
 *
 * Layout: Linux 5.15 UAPI (struct added in Linux 5.9,
 * ingress_ifindex added in Linux 5.12).
 * ========================================================================= */

/* Helper macro to embed a pointer inside a BPF context struct while
 * keeping the overall struct 8-byte aligned. */
#ifndef __bpf_md_ptr
#  define __bpf_md_ptr(type, name)              \
    union {                                     \
        type name;                              \
        __u64 :64;                              \
    } __attribute__((aligned(8)))
#endif

struct bpf_sk_lookup {
    __bpf_md_ptr(struct bpf_sock *, sk); /* Selected socket (output)        */
    __u32 family;          /* Protocol family (AF_INET / AF_INET6)           */
    __u32 protocol;        /* IP protocol    (IPPROTO_TCP / IPPROTO_UDP)     */
    __u32 remote_ip4;      /* Network byte order                             */
    __u32 remote_ip6[4];   /* Network byte order                             */
    __be16 remote_port;    /* Network byte order                             */
    __u16 :16;             /* Zero padding                                   */
    __u32 local_ip4;       /* Network byte order                             */
    __u32 local_ip6[4];    /* Network byte order                             */
    __u32 local_port;      /* Host byte order                                */
    __u32 ingress_ifindex; /* Arriving interface index (Linux 5.12+)         */
};

#endif /* __TINYTUN_LINUX_BPF_H */
