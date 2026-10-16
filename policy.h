/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CSUMGUARD_POLICY_H
#define CSUMGUARD_POLICY_H
/* CSG_PACKET_TYPE and CSG_READ are supplied by the BPF or native adapter.
 * No private sk_buff checksum metadata is visible to this policy. */
#ifndef EGRESS_MTU
#define EGRESS_MTU 1500
#endif
#if EGRESS_MTU < 68 || EGRESS_MTU > 65535
#error EGRESS_MTU must be within 68..65535
#endif
#ifndef CSG_INLINE
#define CSG_INLINE static inline __attribute__((always_inline))
#endif
enum csg_reason {
 CSG_PASS_IPV4, CSG_PASS_ARP, CSG_DROP_OFFLOAD, CSG_DROP_VLAN,
 CSG_DROP_L2, CSG_DROP_TRUNCATED, CSG_DROP_IP, CSG_DROP_FRAGMENT,
 CSG_DROP_MTU, CSG_DROP_TRANSPORT, CSG_DROP_ARP, CSG_REASON_COUNT
};
CSG_INLINE unsigned csg_be16(const unsigned char *p)
{ return ((unsigned)p[0] << 8) | p[1]; }
CSG_INLINE int csg_is_pass(enum csg_reason r)
{ return r == CSG_PASS_IPV4 || r == CSG_PASS_ARP; }
#ifdef CSG_PACKET_TYPE
CSG_INLINE enum csg_reason csg_classify(CSG_PACKET_TYPE *p)
{
 unsigned char eth[14], ip[20], tr[20];
 unsigned total, transport, frag, sum = 0;
 if (p->gso_size || p->gso_segs > 1) return CSG_DROP_OFFLOAD;
 if (p->vlan_present) return CSG_DROP_VLAN;
 if (CSG_READ(p, 0, eth, sizeof(eth))) return CSG_DROP_TRUNCATED;
 unsigned proto = csg_be16(eth + 12);
 /* Both wire bytes and the stack's protocol must agree. */
 #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
 if ((p->protocol & ~0xffffu) ||
     proto != __builtin_bswap16((unsigned short)p->protocol)) return CSG_DROP_L2;
#else
 if (proto != p->protocol) return CSG_DROP_L2;
#endif
 if (proto == 0x8100 || proto == 0x88a8 || proto == 0x9100) return CSG_DROP_VLAN;
 if (proto == 0x0806) {
  unsigned char arp[28];
  if (p->len < 42 || CSG_READ(p, 14, arp, sizeof(arp))) return CSG_DROP_TRUNCATED;
  if (p->len > 60 || csg_be16(arp) != 1 || csg_be16(arp+2) != 0x0800 ||
      arp[4] != 6 || arp[5] != 4 ||
      (csg_be16(arp+6) != 1 && csg_be16(arp+6) != 2)) return CSG_DROP_ARP;
  return CSG_PASS_ARP;
 }
 if (proto != 0x0800) return CSG_DROP_L2;
 if (CSG_READ(p, 14, ip, sizeof(ip))) return CSG_DROP_TRUNCATED;
 /* v4, no options. A separate reviewed profile is required for options. */
 if (ip[0] != 0x45) return CSG_DROP_IP;
 total = csg_be16(ip+2);
 if (total < 20) return CSG_DROP_IP;
 if (p->len < 14 + total) return CSG_DROP_TRUNCATED;
 /* Permit ordinary minimum-frame Ethernet padding, not arbitrary suffixes. */
 if (p->len > 14 + total && p->len > 60) return CSG_DROP_IP;
 if (total > EGRESS_MTU || p->len > 14 + EGRESS_MTU) return CSG_DROP_MTU;
 frag = csg_be16(ip+6);
 if (frag & 0xbfff) return CSG_DROP_FRAGMENT; /* reserved, MF, or offset; DF allowed */
#ifdef __clang__
#pragma unroll
#endif
 for (unsigned i = 0; i < 20; i += 2) sum += csg_be16(ip+i);
 sum = (sum & 0xffff) + (sum >> 16);
 sum = (sum & 0xffff) + (sum >> 16);
 if (sum != 0xffff || !ip[8]) return CSG_DROP_IP;
 transport = total - 20;
 if (ip[9] == 6) {
  unsigned char opt_end;
  if (transport < 20 || CSG_READ(p, 34, tr, 20)) return CSG_DROP_TRANSPORT;
  unsigned hdr = (tr[12] >> 4) * 4;
  if (hdr < 20 || hdr > transport || !csg_be16(tr) || !csg_be16(tr+2) ||
      (hdr > 20 && CSG_READ(p, 34 + hdr - 1, &opt_end, 1)))
   return CSG_DROP_TRANSPORT;
  /* Packet length and option-tail read establish full options are present. */
 } else if (ip[9] == 17) {
  if (transport < 8 || CSG_READ(p, 34, tr, 8)) return CSG_DROP_TRANSPORT;
  if (csg_be16(tr+4) != transport || !csg_be16(tr+2)) return CSG_DROP_TRANSPORT;
 } else return CSG_DROP_TRANSPORT;
 return CSG_PASS_IPV4;
}
#endif
#endif
