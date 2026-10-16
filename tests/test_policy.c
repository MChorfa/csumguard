/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#ifdef __linux__
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#else
typedef uint8_t __u8;
typedef uint16_t __be16;
typedef uint32_t __u32;
#define ETH_HLEN 14
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
struct iphdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
 uint8_t ihl:4, version:4;
#else
 uint8_t version:4, ihl:4;
#endif
 uint8_t tos;
 uint16_t tot_len, id, frag_off;
 uint8_t ttl, protocol;
 uint16_t check;
 uint32_t saddr, daddr;
};
#endif
struct packet {
 unsigned len, gso_size, gso_segs, vlan_present;
 unsigned protocol;
 unsigned char data[65550];
};
static int load(struct packet *p, unsigned off, void *out, unsigned len)
{
 if (off > p->len || len > p->len-off || off+len > sizeof(p->data)) return -1;
 memcpy(out,p->data+off,len);return 0;
}
#define CSG_PACKET_TYPE struct packet
#define CSG_READ load
#include "../policy.h"
#include "../detect_policy.h"
#define bpf_skb_load_bytes load
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16((unsigned short)(x))
#else
#define bpf_htons(x) (x)
#endif
#define verdict(x) (x)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#include "legacy_tc_body.h"
#pragma GCC diagnostic pop
static void be16(unsigned char *p,unsigned n) { p[0]=(unsigned char)(n>>8);p[1]=(unsigned char)(n&255); }
static void checksum(struct packet *p)
{
 unsigned char *ip=p->data+14;ip[10]=ip[11]=0;unsigned sum=0;
 for (unsigned i=0;i<20;i+=2) sum+=csg_be16(ip+i);
 sum=(sum&65535)+(sum>>16);sum=(sum&65535)+(sum>>16);
 be16(ip+10,(~sum)&65535);
}
static struct packet ipv4(unsigned size,unsigned proto)
{
 struct packet p={0};assert(size>=40 && size+14<=sizeof(p.data));
 p.len=14+size;p.protocol=bpf_htons(0x0800);be16(p.data+12,0x0800);
 p.data[14]=0x45;be16(p.data+16,size);p.data[22]=64;p.data[23]=(unsigned char)proto;
 p.data[26]=10;p.data[29]=2;p.data[30]=10;p.data[33]=1;
 be16(p.data+34,12345);be16(p.data+36,443);
 if (proto==6) p.data[46]=0x50;
 if (proto==17) be16(p.data+38,size-20);
 checksum(&p);return p;
}
static unsigned tests;
static void expect(const char *name,struct packet *p,enum csg_reason expected)
{
 enum csg_reason got=csg_classify(p);
 if (got!=expected) { fprintf(stderr,"FAIL %s: got %u expected %u\n",name,got,expected);exit(1); }
 tests++;
}
int main(void)
{
 const unsigned small = EGRESS_MTU < 100 ? EGRESS_MTU : 100;
 struct packet p=ipv4(small,6);
 expect("TCP positive",&p,CSG_PASS_IPV4);
 p=ipv4(small,17);expect("UDP positive",&p,CSG_PASS_IPV4);
 p=ipv4(EGRESS_MTU,6);expect("MTU inclusive",&p,CSG_PASS_IPV4);
 if (EGRESS_MTU < 65535) { p=ipv4(EGRESS_MTU+1,6);expect("MTU exceeded",&p,CSG_DROP_MTU); }
 p=ipv4(40,6);p.len=60;expect("Ethernet minimum padding",&p,CSG_PASS_IPV4);
 p.len=61;expect("excess suffix",&p,CSG_DROP_IP);
 p=ipv4(40,6);be16(p.data+20,0x4000);checksum(&p);expect("DF allowed",&p,CSG_PASS_IPV4);
 p=ipv4(small,17);be16(p.data+20,0x2000);checksum(&p);
 assert(legacy_classify(&p)==TC_ACT_OK);expect("small first fragment regression",&p,CSG_DROP_FRAGMENT);
 be16(p.data+20,1);checksum(&p);assert(legacy_classify(&p)==TC_ACT_OK);
 expect("small later fragment regression",&p,CSG_DROP_FRAGMENT);
 be16(p.data+20,0x8000);checksum(&p);expect("reserved fragment flag",&p,CSG_DROP_FRAGMENT);
 p=ipv4(small,6);p.gso_size=8;assert(legacy_classify(&p)==TC_ACT_OK);
 expect("GSO regression",&p,CSG_DROP_OFFLOAD);
 p=ipv4(small,6);p.gso_segs=2;expect("GSO segment metadata",&p,CSG_DROP_OFFLOAD);
 p=ipv4(small,6);p.vlan_present=1;expect("accelerated VLAN",&p,CSG_DROP_VLAN);
 p=ipv4(small,6);be16(p.data+12,0x8100);p.protocol=bpf_htons(0x8100);expect("inline VLAN",&p,CSG_DROP_VLAN);
 be16(p.data+12,0x88a8);p.protocol=bpf_htons(0x88a8);expect("QinQ",&p,CSG_DROP_VLAN);
 be16(p.data+12,0x9100);p.protocol=bpf_htons(0x9100);expect("QinQ 0x9100",&p,CSG_DROP_VLAN);
 p=ipv4(small,6);be16(p.data+12,0x86dd);p.protocol=bpf_htons(0x86dd);
 assert(legacy_classify(&p)==TC_ACT_OK);expect("IPv6 regression",&p,CSG_DROP_L2);
 p=ipv4(small,6);be16(p.data+12,50);p.protocol=bpf_htons(50);expect("802.3 LLC",&p,CSG_DROP_L2);
 p=ipv4(small,6);p.protocol=0;expect("wire/context mismatch",&p,CSG_DROP_L2);
 p=ipv4(small,6);p.protocol|=0x10000u;expect("dirty upper protocol bits",&p,CSG_DROP_L2);
 p=ipv4(small,6);p.len=13;expect("short Ethernet",&p,CSG_DROP_TRUNCATED);
 p=ipv4(small,6);p.len=33;expect("short IP",&p,CSG_DROP_TRUNCATED);
 p=ipv4(small,6);p.len--;assert(legacy_classify(&p)==TC_ACT_OK);expect("short declared IP",&p,CSG_DROP_TRUNCATED);
 p=ipv4(small,6);p.data[14]=0x46;expect("IP options denied",&p,CSG_DROP_IP);
 p=ipv4(small,6);p.data[14]=0x65;expect("bad IP version",&p,CSG_DROP_IP);
 p=ipv4(small,6);be16(p.data+16,19);expect("short total length",&p,CSG_DROP_IP);
 p=ipv4(small,6);p.data[24]^=1;expect("bad IP checksum",&p,CSG_DROP_IP);
 p=ipv4(small,6);p.data[22]=0;checksum(&p);expect("zero TTL",&p,CSG_DROP_IP);
 p=ipv4(40,6);p.data[46]=0x40;expect("short TCP doff",&p,CSG_DROP_TRANSPORT);
 p.data[46]=0xf0;expect("TCP length exceeds IP",&p,CSG_DROP_TRANSPORT);
 p=ipv4(small,6);p.data[46]=0x60;expect("TCP options present",&p,CSG_PASS_IPV4);
 p=ipv4(small,6);be16(p.data+34,0);expect("TCP zero source port",&p,CSG_DROP_TRANSPORT);
 p=ipv4(small,6);be16(p.data+36,0);expect("TCP zero port",&p,CSG_DROP_TRANSPORT);
 p=ipv4(small,17);be16(p.data+38,79);expect("UDP/IP mismatch",&p,CSG_DROP_TRANSPORT);
 p=ipv4(small,17);be16(p.data+36,0);expect("UDP destination zero",&p,CSG_DROP_TRANSPORT);
 p=ipv4(small,47);expect("GRE denied",&p,CSG_DROP_TRANSPORT);
 p=ipv4(small,4);expect("IP-in-IP denied",&p,CSG_DROP_TRANSPORT);
 p=ipv4(small,1);expect("ICMP not in restricted profile",&p,CSG_DROP_TRANSPORT);
 p=(struct packet){0};p.len=42;p.protocol=bpf_htons(0x0806);be16(p.data+12,0x0806);
 be16(p.data+14,1);be16(p.data+16,0x0800);p.data[18]=6;p.data[19]=4;be16(p.data+20,1);
 expect("ARP request",&p,CSG_PASS_ARP);be16(p.data+20,2);expect("ARP reply",&p,CSG_PASS_ARP);
 p.len=60;expect("padded ARP",&p,CSG_PASS_ARP);p.len=61;expect("oversize ARP",&p,CSG_DROP_ARP);
 p.len=42;p.data[18]=8;expect("bad ARP address size",&p,CSG_DROP_ARP);
 assert(!csg_suspicious(2,0x45,14,0));tests++; /* COMPLETE union must not alert */
 assert(!csg_suspicious(0,0x45,14,0));tests++;
 assert(csg_suspicious(3,0x45,14,33));tests++;
 assert(!csg_suspicious(3,0x45,14,34));tests++;
 assert(!csg_suspicious(3,0x65,14,0));tests++;
 assert(!csg_suspicious(3,0x44,14,0));tests++; /* IHL < 5 must not alert */
 assert(!csg_suspicious(3,0x45,0xffff,0));tests++; /* unset network_header (0xffff) */
 assert(!csg_suspicious(3,0x45,0xffff,0xffff));tests++;
 assert(!csg_suspicious(3,0x45,0xffec,0xffe0));tests++; /* 16-bit nh+ihl overflow (0x10000) */
 assert(csg_suspicious(3,0x45,0xffeb,0xfffe));tests++; /* max valid 16-bit nh+ihl (0xffff) */
 assert(!csg_suspicious(3,0x45,0xffeb,0xffff));tests++; /* start == nh+ihl not suspicious */
 assert(!csg_suspicious(3,0x4f,0xffc4,0));tests++; /* IHL=60 overflow */
 assert(csg_suspicious(3,0x4f,0xffc3,0xfffe));tests++; /* IHL=60 max valid */
 /* Deterministic truncation sweep across a valid packet: no truncated prefix passes. */
 p=ipv4(small,6);
 for (unsigned len=0;len<small+14;len++) { p.len=len;assert(!csg_is_pass(csg_classify(&p)));tests++; }
 /* Every nonzero fragment offset and MF combination must deny a valid small frame. */
 for (unsigned f=1;f<=0x3fff;f++) {
  p=ipv4(small,17);be16(p.data+20,f);checksum(&p);
  assert(csg_classify(&p)==CSG_DROP_FRAGMENT);tests++;
 }
 printf("PASS %u native policy/predicate checks; 5 legacy acceptance checks across 4 classes reproduced\n",tests);
 return 0;
}
