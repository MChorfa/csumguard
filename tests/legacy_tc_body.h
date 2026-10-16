/* SPDX-License-Identifier: GPL-2.0 */
/* Original function body, renamed and native helper-adapted for regression only. */
int legacy_classify(struct packet *skb)
{
	/* cls_bpf at ingress exposes the frame starting at the MAC header. */
	__u32 l3 = ETH_HLEN;
	__be16 proto = skb->protocol;

#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (proto != bpf_htons(ETH_P_8021Q) &&
		    proto != bpf_htons(ETH_P_8021AD))
			break;
		struct { __be16 tci; __be16 encap; } v;
		if (bpf_skb_load_bytes(skb, l3, &v, sizeof(v)))
			return verdict(TC_ACT_SHOT);
		proto = v.encap;
		l3 += sizeof(v);
	}
	if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD))
		return verdict(TC_ACT_SHOT);	/* >2 tags: not expected from a guest */

	if (proto != bpf_htons(ETH_P_IP))
		return verdict(TC_ACT_OK);	/* IPv4-only guard */

	struct iphdr ip;
	if (bpf_skb_load_bytes(skb, l3, &ip, sizeof(ip)))
		return verdict(TC_ACT_SHOT);

	__u32 ihl = ip.ihl * 4;
	if (ip.version != 4 || ihl < sizeof(ip))
		return verdict(TC_ACT_SHOT);

	/* Largest L3 packet this skb can turn into on the way out. */
	__u32 need;
	if (skb->gso_size) {
		__u32 l4;
		if (ip.protocol == IPPROTO_TCP) {
			__u8 doff;
			if (bpf_skb_load_bytes(skb, l3 + ihl + 12, &doff, 1))
				return verdict(TC_ACT_SHOT);
			l4 = (doff >> 4) * 4;
		} else if (ip.protocol == IPPROTO_UDP) {
			l4 = 8;
		} else {
			return verdict(TC_ACT_SHOT);
		}
		need = ihl + l4 + skb->gso_size;
	} else {
		need = skb->len - l3;
	}

	if (need > EGRESS_MTU)
		return verdict(TC_ACT_SHOT);	/* would need fragmentation */
	return verdict(TC_ACT_OK);
}

