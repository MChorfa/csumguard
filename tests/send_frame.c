/* SPDX-License-Identifier: GPL-2.0 */
/* Ordinary packet-policy fixtures; no virtio metadata or CVE exploit. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#ifdef __linux__
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#endif

struct csg_test_packet {
 unsigned len, gso_size, gso_segs, vlan_present;
 unsigned protocol;
 unsigned char data[2048];
};

static int csg_test_read(struct csg_test_packet *p, unsigned off, void *out, unsigned len)
{
 if (off > p->len || len > p->len - off || off + len > sizeof(p->data))
  return -1;
 memcpy(out, p->data + off, len);
 return 0;
}

#define CSG_PACKET_TYPE struct csg_test_packet
#define CSG_READ csg_test_read
#include "../policy.h"

static void put_be16(unsigned char *p, uint16_t v)
{
 p[0] = (unsigned char)(v >> 8);
 p[1] = (unsigned char)(v & 0xffu);
}

static uint16_t ipv4_checksum(const unsigned char *hdr)
{
 uint32_t total = 0;
 for (unsigned i = 0; i < 20; i += 2)
  total += ((uint32_t)hdr[i] << 8) | (uint32_t)hdr[i + 1];
 total = (total & 0xffffu) + (total >> 16);
 total = (total & 0xffffu) + (total >> 16);
 return (uint16_t)((~total) & 0xffffu);
}

static int build_frame(const char *kind, unsigned char *buf, size_t cap,
                       size_t *out_len, uint16_t *out_eth_proto,
                       enum csg_reason *out_expected)
{
 static const unsigned char dst[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
 static const unsigned char src[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
 static const unsigned char spa[4] = { 10, 200, 0, 2 };
 static const unsigned char tpa[4] = { 10, 200, 0, 1 };

 if (!kind || !buf || cap < 1614 || !out_len)
  return -1;
 memset(buf, 0, cap);
 memcpy(buf, dst, 6);
 memcpy(buf + 6, src, 6);

 if (strcmp(kind, "arp") == 0) {
  put_be16(buf + 12, 0x0806);
  put_be16(buf + 14, 1);
  put_be16(buf + 16, 0x0800);
  buf[18] = 6;
  buf[19] = 4;
  put_be16(buf + 20, 1);
  memcpy(buf + 22, src, 6);
  memcpy(buf + 28, spa, 4);
  memset(buf + 32, 0, 6);
  memcpy(buf + 38, tpa, 4);
  *out_len = 42;
  if (out_eth_proto) *out_eth_proto = 0x0806;
  if (out_expected) *out_expected = CSG_PASS_ARP;
  return 0;
 }

 if (strcmp(kind, "ipv6") == 0) {
  put_be16(buf + 12, 0x86dd);
  buf[14] = 0x60;
  memset(buf + 15, 0, 39);
  *out_len = 54;
  if (out_eth_proto) *out_eth_proto = 0x86dd;
  if (out_expected) *out_expected = CSG_DROP_L2;
  return 0;
 }

 uint16_t length = 100;
 uint16_t flags = 0;
 enum csg_reason expected = CSG_PASS_IPV4;
 if (strcmp(kind, "udp") == 0) {
  length = 100;
  flags = 0;
  expected = CSG_PASS_IPV4;
 } else if (strcmp(kind, "oversize") == 0) {
  length = 1600;
  flags = 0;
  expected = CSG_DROP_MTU;
 } else if (strcmp(kind, "first-fragment") == 0) {
  length = 100;
  flags = 0x2000;
  expected = CSG_DROP_FRAGMENT;
 } else if (strcmp(kind, "later-fragment") == 0) {
  length = 100;
  flags = 0x0001;
  expected = CSG_DROP_FRAGMENT;
 } else {
  return -1;
 }

 put_be16(buf + 12, 0x0800);
 unsigned char *ip = buf + 14;
 ip[0] = 0x45;
 ip[1] = 0x00;
 put_be16(ip + 2, length);
 put_be16(ip + 4, 1);
 put_be16(ip + 6, flags);
 ip[8] = 64;
 ip[9] = 17;
 put_be16(ip + 10, 0);
 memcpy(ip + 12, spa, 4);
 memcpy(ip + 16, tpa, 4);
 put_be16(ip + 10, ipv4_checksum(ip));

 unsigned char *udp = ip + 20;
 put_be16(udp + 0, 12345);
 put_be16(udp + 2, 443);
 put_be16(udp + 4, (uint16_t)(length - 20));
 put_be16(udp + 6, 0);
 memset(udp + 8, 'A', (size_t)(length - 28));

 *out_len = 14u + (size_t)length;
 if (out_eth_proto) *out_eth_proto = 0x0800;
 if (out_expected) *out_expected = expected;
 return 0;
}

static uint16_t host_to_be16(uint16_t v)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
 return __builtin_bswap16(v);
#else
 return v;
#endif
}

static int run_self_test(void)
{
 static const char *const kinds[] = {
  "udp", "arp", "ipv6", "oversize", "first-fragment", "later-fragment"
 };
 for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
  struct csg_test_packet pkt;
  memset(&pkt, 0, sizeof(pkt));
  size_t frame_len = 0;
  uint16_t eth_proto = 0;
  enum csg_reason expected = CSG_REASON_COUNT;
  if (build_frame(kinds[i], pkt.data, sizeof(pkt.data),
                  &frame_len, &eth_proto, &expected) != 0) {
   fprintf(stderr, "FAIL send_frame self-test build: %s\n", kinds[i]);
   return 1;
  }
  pkt.len = (unsigned)frame_len;
  pkt.protocol = host_to_be16(eth_proto);
  if (EGRESS_MTU == 1500) {
   enum csg_reason got = csg_classify(&pkt);
   if (got != expected) {
    fprintf(stderr, "FAIL send_frame self-test classify %s: got %u expected %u\n",
            kinds[i], (unsigned)got, (unsigned)expected);
    return 1;
   }
  }
 }
 if (build_frame("invalid-kind", NULL, 0, NULL, NULL, NULL) == 0) {
  fprintf(stderr, "FAIL send_frame accepted invalid kind\n");
  return 1;
 }
 printf("PASS send_frame 6 fixture frame builds verified\n");
 return 0;
}

int main(int argc, char **argv)
{
 if (argc == 2 && strcmp(argv[1], "--self-test") == 0)
  return run_self_test();

 if (argc == 3 && strcmp(argv[1], "--dump-hex") == 0) {
  unsigned char buf[2048];
  size_t len = 0;
  if (build_frame(argv[2], buf, sizeof(buf), &len, NULL, NULL) != 0) {
   fprintf(stderr, "unknown fixture\n");
   return 1;
  }
  for (size_t i = 0; i < len; i++)
   printf("%02x", buf[i]);
  putchar('\n');
  return 0;
 }

 if (argc != 3) {
  fprintf(stderr, "usage: %s <interface> <udp|arp|ipv6|oversize|first-fragment|later-fragment>\n"
                  "       %s --self-test\n"
                  "       %s --dump-hex <kind>\n",
          argv[0], argv[0], argv[0]);
  return 2;
 }

 unsigned char buf[2048];
 size_t len = 0;
 uint16_t eth_proto = 0;
 if (build_frame(argv[2], buf, sizeof(buf), &len, &eth_proto, NULL) != 0) {
  fprintf(stderr, "unknown fixture\n");
  return 1;
 }

#ifdef __linux__
 unsigned ifindex = if_nametoindex(argv[1]);
 if (ifindex == 0) {
  perror("if_nametoindex");
  return 1;
 }
 int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, (int)host_to_be16(ETH_P_ALL));
 if (fd < 0) {
  perror("socket(AF_PACKET)");
  return 1;
 }
 struct sockaddr_ll sll;
 memset(&sll, 0, sizeof(sll));
 sll.sll_family = AF_PACKET;
 sll.sll_ifindex = (int)ifindex;
 sll.sll_protocol = host_to_be16(ETH_P_ALL);
 if (bind(fd, (const struct sockaddr *)&sll, sizeof(sll)) != 0) {
  perror("bind(AF_PACKET)");
  close(fd);
  return 1;
 }
 ssize_t sent = send(fd, buf, len, 0);
 if (sent < 0 || (size_t)sent != len) {
  perror("send");
  close(fd);
  return 1;
 }
 close(fd);
 return 0;
#else
 (void)eth_proto;
 fprintf(stderr, "AF_PACKET raw socket send requires Linux\n");
 return 77;
#endif
}
