/* SPDX-License-Identifier: GPL-2.0 */
/* attach is only allowed on a DOWN interface with a new clsact hook.
 * status is a read-only identity/counter check, not continuous protection. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <openssl/evp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "policy.h"

#define CSG_HANDLE 0xc501
#define CSG_PRIORITY 1
#define REASONS CSG_REASON_COUNT

static const char *const names[CSG_REASON_COUNT] = {
 [CSG_PASS_IPV4]      = "pass_ipv4",
 [CSG_PASS_ARP]       = "pass_arp",
 [CSG_DROP_OFFLOAD]   = "drop_offload",
 [CSG_DROP_VLAN]      = "drop_vlan",
 [CSG_DROP_L2]        = "drop_l2",
 [CSG_DROP_TRUNCATED] = "drop_truncated",
 [CSG_DROP_IP]        = "drop_ip",
 [CSG_DROP_FRAGMENT]  = "drop_fragment",
 [CSG_DROP_MTU]       = "drop_mtu",
 [CSG_DROP_TRANSPORT] = "drop_transport",
 [CSG_DROP_ARP]       = "drop_arp",
};

_Static_assert(REASONS == 11, "CSG_REASON_COUNT changed; update names[] table");
_Static_assert(sizeof(names) / sizeof(names[0]) == CSG_REASON_COUNT,
               "names[] array size must equal CSG_REASON_COUNT");

static int number(const char *s, unsigned *v)
{
 char *end; unsigned long n;
 if (!s || *s < '1' || *s > '9') return -1;
 errno = 0; n = strtoul(s, &end, 10);
 if (errno || *end || n > UINT_MAX) return -1;
 *v = (unsigned)n; return 0;
}

static int iface_down(const char *name)
{
 if (!name) { errno = EINVAL; return -1; }
 size_t len = strlen(name);
 if (len == 0 || len >= IFNAMSIZ) { errno = EINVAL; return -1; }
 struct ifreq req = {};
 int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
 if (fd < 0) return -1;
 memcpy(req.ifr_name, name, len + 1);
 int err = ioctl(fd, SIOCGIFFLAGS, &req);
 close(fd);
 if (err) return -1;
 return !(req.ifr_flags & IFF_UP);
}

static int open_verified_path(const char *path)
{
 if (!path || path[0] != '/') { errno = EINVAL; return -1; }
 int dirfd = open("/", O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
 if (dirfd < 0) return -1;
 struct stat dst;
 if (fstat(dirfd, &dst) || !S_ISDIR(dst.st_mode) ||
     dst.st_uid != 0 || (dst.st_mode & 022)) {
  close(dirfd); errno = EPERM; return -1;
 }
 const char *p = path;
 while (*p == '/') p++;
 if (!*p) { close(dirfd); errno = EINVAL; return -1; }
 for (;;) {
  const char *slash = strchr(p, '/');
  size_t clen = slash ? (size_t)(slash - p) : strlen(p);
  if (clen == 0 || clen >= NAME_MAX ||
      (clen == 1 && p[0] == '.') ||
      (clen == 2 && p[0] == '.' && p[1] == '.')) {
   close(dirfd); errno = EINVAL; return -1;
  }
  char comp[NAME_MAX];
  memcpy(comp, p, clen);
  comp[clen] = '\0';
  if (slash) {
   while (*slash == '/') slash++;
   if (!*slash) { close(dirfd); errno = EINVAL; return -1; }
   int nextfd = openat(dirfd, comp, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
   close(dirfd);
   if (nextfd < 0) return -1;
   if (fstat(nextfd, &dst) || !S_ISDIR(dst.st_mode) ||
       dst.st_uid != 0 || (dst.st_mode & 022)) {
    close(nextfd); errno = EPERM; return -1;
   }
   dirfd = nextfd;
   p = slash;
  } else {
   int fd = openat(dirfd, comp, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
   close(dirfd);
   return fd;
  }
 }
}

static struct bpf_object *verified_object(const char *path, const char *want)
{
 if (!path || !want || path[0] != '/' || strlen(want) != 64) {
  errno = EINVAL; return NULL;
 }
 for (unsigned i = 0; i < 64; i++)
  if (!((want[i] >= '0' && want[i] <= '9') || (want[i] >= 'a' && want[i] <= 'f')))
   { errno = EINVAL; return NULL; }
 int fd = open_verified_path(path);
 if (fd < 0) return NULL;
 struct stat st0, st1;
 if (fstat(fd, &st0) || !S_ISREG(st0.st_mode) || st0.st_uid != 0 ||
     (st0.st_mode & 022) || st0.st_nlink != 1 ||
     st0.st_size <= 0 || st0.st_size > 16 * 1024 * 1024) {
  close(fd); errno = EPERM; return NULL;
 }
 size_t len = (size_t)st0.st_size, used = 0;
 unsigned char *buf = malloc(len);
 if (!buf) { close(fd); return NULL; }
 while (used < len) {
  ssize_t n = read(fd, buf + used, len - used);
  if (n < 0 && errno == EINTR) continue;
  if (n <= 0) { free(buf); close(fd); errno = EIO; return NULL; }
  used += (size_t)n;
 }
 /* Verify true EOF (no concurrent append) and unchanged file metadata. */
 unsigned char extra;
 ssize_t eof_rc;
 do {
  eof_rc = read(fd, &extra, 1);
 } while (eof_rc < 0 && errno == EINTR);
 if (eof_rc != 0 || fstat(fd, &st1) ||
     st1.st_dev != st0.st_dev || st1.st_ino != st0.st_ino ||
     st1.st_size != st0.st_size || st1.st_nlink != 1 ||
     st1.st_uid != 0 || (st1.st_mode & 022) ||
     st1.st_mtime != st0.st_mtime || st1.st_ctime != st0.st_ctime) {
  free(buf); close(fd); errno = EIO; return NULL;
 }
 close(fd);
 unsigned char digest[EVP_MAX_MD_SIZE]; unsigned int size = 0;
 char got[65];
 if (!EVP_Digest(buf, len, digest, &size, EVP_sha256(), NULL) || size != 32) {
  free(buf); errno = EIO; return NULL;
 }
 for (unsigned i = 0; i < 32; i++) snprintf(got + i * 2, 3, "%02x", digest[i]);
 if (strcmp(got, want)) { free(buf); errno = EBADMSG; return NULL; }
 /* Hash and parse the very same snapshot, without reopening the path. */
 struct bpf_object *obj = bpf_object__open_mem(buf, len, NULL);
 free(buf);
 if (!obj || libbpf_get_error(obj)) { errno = EINVAL; return NULL; }
 return obj;
}

static int read_stats(int prog_fd, uint64_t totals[static CSG_REASON_COUNT])
{
 memset(totals, 0, sizeof(uint64_t) * CSG_REASON_COUNT);
 struct bpf_prog_info info = {}; __u32 size = sizeof(info);
 if (bpf_obj_get_info_by_fd(prog_fd, &info, &size)) return -1;
 if (!info.nr_map_ids || info.nr_map_ids > 1024) { errno = EOVERFLOW; return -1; }
 __u32 count = info.nr_map_ids;
 __u32 *ids = calloc(count, sizeof(*ids));
 if (!ids) return -1;
 memset(&info, 0, sizeof(info)); size = sizeof(info);
 info.nr_map_ids = count; info.map_ids = (__u64)(uintptr_t)ids;
 if (bpf_obj_get_info_by_fd(prog_fd, &info, &size) || info.nr_map_ids > count) {
  free(ids); return -1;
 }
 int map = -1;
 for (__u32 i = 0; i < info.nr_map_ids; i++) {
  int fd = bpf_map_get_fd_by_id(ids[i]);
  if (fd < 0) continue;
  struct bpf_map_info mi = {}; __u32 ml = sizeof(mi);
  if (!bpf_obj_get_info_by_fd(fd, &mi, &ml) &&
      !strncmp((char *)mi.name, "csg_stats", BPF_OBJ_NAME_LEN) &&
      mi.type == BPF_MAP_TYPE_PERCPU_ARRAY && mi.key_size == 4 &&
      mi.value_size == 8 && mi.max_entries == CSG_REASON_COUNT) { map = fd; break; }
  close(fd);
 }
 free(ids);
 if (map < 0) { errno = ENOENT; return -1; }
 int ncpu = libbpf_num_possible_cpus();
 if (ncpu <= 0 || (size_t)ncpu > SIZE_MAX / sizeof(uint64_t)) {
  close(map); errno = EOVERFLOW; return -1;
 }
 uint64_t *percpu = calloc((size_t)ncpu, sizeof(*percpu));
 if (!percpu) { close(map); return -1; }
 for (__u32 key = 0; key < CSG_REASON_COUNT; key++) {
  if (bpf_map_lookup_elem(map, &key, percpu)) { free(percpu); close(map); return -1; }
  for (int c = 0; c < ncpu; c++) {
   if (UINT64_MAX - totals[key] < percpu[c])
    totals[key] = UINT64_MAX;
   else
    totals[key] += percpu[c];
  }
 }
 free(percpu); close(map);
 return 0;
}

static int emit_json(const char *iface, unsigned idx, unsigned long long netns_ino,
                     unsigned prog_id, const uint64_t totals[static CSG_REASON_COUNT])
{
 char out[2048];
 int n = snprintf(out, sizeof(out),
                  "{\"interface\":\"%s\",\"ifindex\":%u,\"netns_inode\":%llu,\"prog_id\":%u,\"counters\":{",
                  iface, idx, netns_ino, prog_id);
 if (n < 0 || (size_t)n >= sizeof(out)) { errno = EOVERFLOW; return -1; }
 size_t off = (size_t)n;
 for (unsigned k = 0; k < CSG_REASON_COUNT; k++) {
  n = snprintf(out + off, sizeof(out) - off, "%s\"%s\":%llu",
               k ? "," : "", names[k], (unsigned long long)totals[k]);
  if (n < 0 || (size_t)n >= sizeof(out) - off) { errno = EOVERFLOW; return -1; }
  off += (size_t)n;
 }
 n = snprintf(out + off, sizeof(out) - off, "}}\n");
 if (n < 0 || (size_t)n >= sizeof(out) - off) { errno = EOVERFLOW; return -1; }
 off += (size_t)n;
 if (fwrite(out, 1, off, stdout) != off || fflush(stdout) != 0) return -1;
 return 0;
}

static int query(struct bpf_tc_hook *hook, unsigned expected, unsigned *id)
{
 LIBBPF_OPTS(bpf_tc_opts, opt, .handle = CSG_HANDLE, .priority = CSG_PRIORITY);
 int err = bpf_tc_query(hook, &opt);
 if (err || !opt.prog_id || (expected && opt.prog_id != expected)) {
  fprintf(stderr, "attachment identity mismatch or query failure: %d\n", err);
  return -1;
 }
 *id = opt.prog_id; return 0;
}

int main(int argc, char **argv)
{
 if (argc < 3 || strlen(argv[2]) >= IFNAMSIZ) goto usage;
 int attaching = !strcmp(argv[1], "attach");
 if ((attaching && argc != 5) || (!attaching && (strcmp(argv[1], "status") || argc != 6))) goto usage;
 /* Avoid ambiguous names and JSON escaping: Linux's usual simple interface names. */
 for (const char *s = argv[2]; *s; s++)
  if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
        (*s >= '0' && *s <= '9') || *s == '_' || *s == '-' || *s == '.')) goto usage;
 unsigned idx = if_nametoindex(argv[2]), expected = 0, wantidx = 0;
 if (!idx) { perror("interface"); return 1; }
 struct stat ns;
 if (stat("/proc/self/ns/net", &ns) || !ns.st_ino) { perror("netns"); return 1; }
 if (!attaching) {
  char *end; errno = 0;
  unsigned long long n = strtoull(argv[4], &end, 10);
  if (*argv[4] < '1' || *argv[4] > '9' || *end || errno || n != (unsigned long long)ns.st_ino ||
      number(argv[3], &wantidx) || wantidx != idx || number(argv[5], &expected)) {
   fprintf(stderr, "invalid or stale interface/netns/program identity\n"); return 1;
  }
 }
 LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = (int)idx, .attach_point = BPF_TC_INGRESS);
 struct bpf_object *obj = NULL;
 unsigned id = 0;
 int hook_created = 0;
 int filter_attached = 0;
 if (attaching) {
  if (iface_down(argv[2]) != 1) { fprintf(stderr, "interface must be DOWN\n"); return 1; }
  obj = verified_object(argv[3], argv[4]);
  if (!obj) { perror("object verification"); return 1; }
  if (bpf_object__load(obj)) { fprintf(stderr, "BPF load failed\n"); goto fail; }
  struct bpf_program *prog = bpf_object__find_program_by_name(obj, "csumguard_in");
  if (!prog) { fprintf(stderr, "program not found\n"); goto fail; }
  struct bpf_prog_info pi = {}; __u32 sz = sizeof(pi);
  if (bpf_obj_get_info_by_fd(bpf_program__fd(prog), &pi, &sz)) goto fail;
  if (if_nametoindex(argv[2]) != idx || iface_down(argv[2]) != 1) {
   fprintf(stderr, "interface changed or came UP before hook creation\n"); goto fail;
  }
  /* Refuse existing clsact; do not override another network policy. */
  int err = bpf_tc_hook_create(&hook);
  if (err) { fprintf(stderr, "new clsact required: %d\n", err); goto fail; }
  hook_created = 1;
  LIBBPF_OPTS(bpf_tc_opts, opt, .prog_fd = bpf_program__fd(prog),
              .handle = CSG_HANDLE, .priority = CSG_PRIORITY);
  err = bpf_tc_attach(&hook, &opt);
  if (!err && !query(&hook, pi.id, &id))
   filter_attached = 1;
  if (err || !filter_attached || iface_down(argv[2]) != 1 || if_nametoindex(argv[2]) != idx) {
   fprintf(stderr, "attach/post-check failed: %d; interface must stay DOWN\n", err);
   goto fail;
  }
 } else if (query(&hook, expected, &id)) return 1;
 int fd = bpf_prog_get_fd_by_id(id);
 if (fd < 0) goto fail;
 uint64_t totals[CSG_REASON_COUNT];
 int err = read_stats(fd, totals);
 close(fd);
 if (err) { perror("counters"); goto fail; }
 if (attaching && (iface_down(argv[2]) != 1 || if_nametoindex(argv[2]) != idx)) {
  fprintf(stderr, "interface must stay DOWN through attach completion\n");
  goto fail;
 }
 if (emit_json(argv[2], idx, (unsigned long long)ns.st_ino, id, totals)) {
  perror("stdout"); goto fail;
 }
 if (obj) bpf_object__close(obj);
 return 0;
fail:
 if (hook_created) {
  /* Never strip an active guard from an interface that concurrently came UP. */
  if (if_nametoindex(argv[2]) == idx && iface_down(argv[2]) == 1) {
   bpf_tc_hook_destroy(&hook);
  } else if (filter_attached) {
   fprintf(stderr, "interface came UP or changed during attach; preserving attached guard (fail-closed)\n");
  }
 }
 if (obj) bpf_object__close(obj);
 return 1;
usage:
 fprintf(stderr, "usage: %s attach IFACE /absolute/guard.o SHA256\n       %s status IFACE IFINDEX NETNS_INODE PROG_ID\n", argv[0], argv[0]);
 return 2;
}
