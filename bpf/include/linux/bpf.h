/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Compatibility shim around the system <linux/bpf.h>.
 *
 * When clang searches for <linux/bpf.h> it finds this file first (because
 * bpf/include/ is placed before /usr/include on the -I list).  We pull in
 * the real system header via #include_next, then add definitions that are
 * absent on older kernel userspace-API headers (linux-libc-dev < 5.9):
 *
 *   struct bpf_sk_lookup   – added in Linux 5.9 (commit 70d66244317e)
 *     ingress_ifindex field – added in Linux 5.12
 *
 * Ubuntu 20.04 ships linux-libc-dev 5.4, so cross-compilation containers
 * based on that release are missing the struct entirely.  This shim lets
 * the BPF C source compile against any kernel header version >= 4.x while
 * still using the correct layout at runtime (the BPF verifier enforces
 * field-access validity at load time).
 */

#ifndef __TINYTUN_LINUX_BPF_COMPAT_H
#define __TINYTUN_LINUX_BPF_COMPAT_H

/* Pull in the real system <linux/bpf.h> (searches the next -I path). */
#include_next <linux/bpf.h>

/* LINUX_VERSION_CODE + KERNEL_VERSION() */
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
/*
 * struct bpf_sk_lookup is completely absent on kernel headers < 5.9.
 * Provide a self-contained definition so that the BPF C source compiles.
 *
 * The layout below matches the kernel 5.12+ definition (which added
 * ingress_ifindex).  Programs accessing ingress_ifindex require a kernel
 * >= 5.12 at runtime; the BPF verifier will reject the program otherwise.
 */

/* __bpf_md_ptr was added in Linux 5.2; expand it manually as a fallback. */
#ifndef __bpf_md_ptr
#define __bpf_md_ptr(type, name)        \
    union {                             \
        type name;                      \
        __u64 :64;                      \
    } __attribute__((aligned(8)))
#endif

/* User-accessible context passed to BPF_PROG_TYPE_SK_LOOKUP programs. */
struct bpf_sk_lookup {
    __bpf_md_ptr(struct bpf_sock *, sk); /* Selected socket (output) */
    __u32 family;          /* Protocol family  (AF_INET / AF_INET6)    */
    __u32 protocol;        /* IP protocol      (IPPROTO_TCP / UDP)     */
    __u32 remote_ip4;      /* Network byte order                       */
    __u32 remote_ip6[4];   /* Network byte order                       */
    __be16 remote_port;    /* Network byte order                       */
    __u16 :16;             /* Zero padding                             */
    __u32 local_ip4;       /* Network byte order                       */
    __u32 local_ip6[4];    /* Network byte order                       */
    __u32 local_port;      /* Host byte order                          */
    __u32 ingress_ifindex; /* Arriving interface (Linux 5.12+)         */
};

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0) */

#endif /* __TINYTUN_LINUX_BPF_COMPAT_H */
