// SPDX-License-Identifier: GPL-2.0
//
// TinyTun eBPF programs
//
// Two programs are compiled into a single object file:
//
//   1. tinytun_tc_egress  – TC classifier attached to the egress path of the
//      outbound network interface.  For each packet whose destination IP is
//      *not* in the skip LPM tries, the packet's skb->mark is set to the
//      configured proxy-mark value so that the policy-routing rule can
//      re-route the packet to the loopback interface.
//
//   2. tinytun_sk_lookup  – sk_lookup program attached to the network
//      namespace.  Runs when the kernel cannot find a listening socket for an
//      incoming TCP connection.  If the arriving packet came from the loopback
//      interface (i.e. was redirected there by policy routing after being
//      marked by tinytun_tc_egress) *and* the destination IP is not in the
//      skip tries, the connection is redirected to TinyTun's IP_TRANSPARENT
//      listening socket stored in the PROXY_SOCK map.
//
// Maps shared by both programs:
//   SKIP_V4   – LPM trie of IPv4 prefixes that should bypass the proxy.
//   SKIP_V6   – LPM trie of IPv6 prefixes that should bypass the proxy.
//   CONFIG    – 1-element array with two u32 entries:
//                 [0] = fwmark value
//                 [1] = loopback interface index
//   PROXY_SOCK – 1-element sockmap holding TinyTun's TCP listening socket.

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* AF_* values are not pulled in by the BPF kernel headers; define them
   directly with their well-known POSIX values. */
#ifndef AF_INET
#define AF_INET  2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* ---- Shared LPM key types ------------------------------------------ */

struct lpm_key_v4 {
    __u32 prefixlen;
    __u32 addr; /* network byte order */
};

struct lpm_key_v6 {
    __u32 prefixlen;
    __u8  addr[16]; /* network byte order */
};

/* ---- BPF Maps -------------------------------------------------------- */

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 512);
    __type(key,   struct lpm_key_v4);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} SKIP_V4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 512);
    __type(key,   struct lpm_key_v6);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} SKIP_V6 SEC(".maps");

/* CONFIG[0] = fwmark, CONFIG[1] = loopback ifindex */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key,   __u32);
    __type(value, __u32);
} CONFIG SEC(".maps");

/* Holds TinyTun's TCP listening socket (index 0). */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, __u32);
} PROXY_SOCK SEC(".maps");

/* ---- Helper: return non-zero if the IPv4 addr should be skipped ------ */

static __always_inline int skip_ipv4(__u32 dst_be)
{
    struct lpm_key_v4 k = {
        .prefixlen = 32,
        .addr      = dst_be,
    };
    return bpf_map_lookup_elem(&SKIP_V4, &k) != NULL;
}

static __always_inline int skip_ipv6(const __u8 *dst)
{
    struct lpm_key_v6 k;
    k.prefixlen = 128;
    __builtin_memcpy(k.addr, dst, 16);
    return bpf_map_lookup_elem(&SKIP_V6, &k) != NULL;
}

/* ================================================================
   Program 1: TC egress classifier
   ================================================================ */

SEC("classifier/egress")
int tinytun_tc_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Look up the configured fwmark. */
    __u32 cfg_key = 0;
    __u32 *mark = bpf_map_lookup_elem(&CONFIG, &cfg_key);
    if (!mark || *mark == 0)
        return TC_ACT_OK;

    /* Parse Ethernet header. */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u16 proto = bpf_ntohs(eth->h_proto);

    if (proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;

        if (skip_ipv4(ip->daddr))
            return TC_ACT_OK;

        /* Mark packet so policy routing sends it to loopback. */
        skb->mark = *mark;

    } else if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_OK;

        if (skip_ipv6(ip6->daddr.s6_addr))
            return TC_ACT_OK;

        skb->mark = *mark;
    }

    return TC_ACT_OK;
}

/* ================================================================
   Program 2: sk_lookup – redirect proxied connections to TinyTun
   ================================================================ */

SEC("sk_lookup/tinytun")
int tinytun_sk_lookup(struct bpf_sk_lookup *ctx)
{
    /* Only handle TCP connections. */
    if (ctx->protocol != IPPROTO_TCP)
        return SK_PASS;

    /* Only redirect packets that arrived on loopback (policy-routed by
       tinytun_tc_egress + the ip rule/route setup in userspace). */
    __u32 lo_key = 1;
    __u32 *lo_ifindex = bpf_map_lookup_elem(&CONFIG, &lo_key);
    if (!lo_ifindex || *lo_ifindex == 0)
        return SK_PASS;
    if (ctx->ingress_ifindex != *lo_ifindex)
        return SK_PASS;

    /* Check skip lists – same logic as in the TC classifier. */
    if (ctx->family == AF_INET) {
        if (skip_ipv4(ctx->local_ip4))
            return SK_PASS;
    } else if (ctx->family == AF_INET6) {
        /* local_ip6 is a __u32[4] in network byte order. */
        if (skip_ipv6((const __u8 *)ctx->local_ip6))
            return SK_PASS;
    } else {
        return SK_PASS;
    }

    /* Redirect to TinyTun's IP_TRANSPARENT listening socket. */
    __u32 key = 0;
    struct bpf_sock *sk = bpf_map_lookup_elem(&PROXY_SOCK, &key);
    if (!sk)
        return SK_PASS;

    int ret = bpf_sk_assign(ctx, sk, 0);
    bpf_sk_release(sk);
    (void)ret;

    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
