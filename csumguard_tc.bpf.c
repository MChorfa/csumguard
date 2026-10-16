// SPDX-License-Identifier: GPL-2.0
/* Restricted IPv4 admission, not a CVE fix. See README.md for assumptions. */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#define CSG_PACKET_TYPE struct __sk_buff
#define CSG_READ(p, off, dst, size) bpf_skb_load_bytes(p, off, dst, size)
#include "policy.h"
struct {
 __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
 __uint(max_entries, CSG_REASON_COUNT);
 __type(key, __u32);
 __type(value, __u64);
} csg_stats SEC(".maps");
SEC("tc")
int csumguard_in(struct __sk_buff *skb)
{
 __u32 reason = csg_classify(skb);
 __u64 *count = bpf_map_lookup_elem(&csg_stats, &reason);
 if (count) (*count)++;
 return csg_is_pass(reason) ? TC_ACT_OK : TC_ACT_SHOT;
}
char LICENSE[] SEC("license") = "GPL";
