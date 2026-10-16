// SPDX-License-Identifier: GPL-2.0
/* Optional counter-only observation. Never blocks or identifies a VM. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "detect_policy.h"
enum { DET_PARTIAL_IPV4, DET_SUSPICIOUS, DET_READ_ERROR, DET_BAD_HEADER, DET_COUNT };
struct {
 __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
 __uint(max_entries, DET_COUNT);
 __type(key, __u32);
 __type(value, __u64);
} csg_detect SEC(".maps");
static __always_inline void inc(__u32 key)
{
 __u64 *v = bpf_map_lookup_elem(&csg_detect, &key);
 if (v) (*v)++;
}
SEC("fentry/skb_checksum_help")
int BPF_PROG(csumguard_detect, struct sk_buff *skb)
{
 __be16 proto;
 unsigned char bitfield_probe;
 if (!skb || bpf_core_read(&proto, sizeof(proto), &skb->protocol)) {
  inc(DET_READ_ERROR); return 0;
 }
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
 if (proto != __builtin_bswap16(0x0800)) return 0;
#else
 if (proto != 0x0800) return 0;
#endif
 if (bpf_probe_read_kernel(&bitfield_probe, sizeof(bitfield_probe),
     (const void *)skb + __builtin_preserve_field_info(skb->ip_summed, BPF_FIELD_BYTE_OFFSET))) {
  inc(DET_READ_ERROR); return 0;
 }
 unsigned state = BPF_CORE_READ_BITFIELD_PROBED(skb, ip_summed);
 if (state != 3) return 0; /* never interpret the checksum union otherwise */
 inc(DET_PARTIAL_IPV4);
 unsigned char *head;
 __u16 nh, start;
 if (bpf_core_read(&head, sizeof(head), &skb->head) ||
     bpf_core_read(&nh, sizeof(nh), &skb->network_header) ||
     bpf_core_read(&start, sizeof(start), &skb->csum_start)) {
  inc(DET_READ_ERROR); return 0;
 }
 unsigned char vhl, ihl_end;
 if (!head || nh == 0xffff ||
     bpf_probe_read_kernel(&vhl, sizeof(vhl), head + nh)) {
  inc(DET_READ_ERROR); return 0;
 }
 unsigned ihl = (unsigned)(vhl & 15u) * 4u;
 if ((vhl >> 4) != 4 || ihl < 20 || nh > 0xffffu - ihl) {
  inc(DET_BAD_HEADER); return 0;
 }
 if (bpf_probe_read_kernel(&ihl_end, sizeof(ihl_end), head + nh + ihl - 1)) {
  inc(DET_READ_ERROR); return 0;
 }
 if (csg_suspicious(state, vhl, nh, start)) inc(DET_SUSPICIOUS);
 return 0;
}
char LICENSE[] SEC("license") = "GPL";
