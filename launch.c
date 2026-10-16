/* SPDX-License-Identifier: GPL-2.0 */
/* Experimental supervised launch in C11. Polling detects loss; it is not atomic
 * continuous enforcement. Run only on a validated dedicated guest TAP path.
 * Operator evidence is an attestation, not automatic kernel-patch verification. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define _DEFAULT_SOURCE 1
#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#include "launch_policy.h"

static volatile sig_atomic_t g_stop_signal = 0;

static void csg_signal_handler(int signum)
{
 if (g_stop_signal == 0)
  g_stop_signal = signum;
}

static uint64_t csg_monotonic_ns(void)
{
 struct timespec ts;
 if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
  return 0;
 return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void csg_Wait_deadline(struct timespec *ts, unsigned timeout_ms)
{
#ifdef __linux__
 clock_gettime(CLOCK_MONOTONIC, ts);
#else
 clock_gettime(CLOCK_REALTIME, ts);
#endif
 uint64_t add_ns = (uint64_t)timeout_ms * 1000000ull;
 ts->tv_sec += (time_t)(add_ns / 1000000000ull);
 ts->tv_nsec += (long)(add_ns % 1000000000ull);
 if (ts->tv_nsec >= 1000000000L) {
  ts->tv_sec += 1;
  ts->tv_nsec -= 1000000000L;
 }
}

/* --- Descriptor-Chained Filesystem Verification (VULN-LAUNCH-006) --- */
static int csg_walk_parent_at(int root_fd, const char *path, uid_t trusted_uid,
                              char leaf_out[NAME_MAX])
{
 if (!path || path[0] != '/' || !leaf_out) {
  errno = EINVAL;
  return -1;
 }
 int dirfd = dup(root_fd);
 if (dirfd < 0)
  return -1;
 struct stat dst;
 if (fstat(dirfd, &dst) != 0 || !S_ISDIR(dst.st_mode) ||
     dst.st_uid != trusted_uid || (dst.st_mode & 022) != 0) {
  close(dirfd);
  errno = EPERM;
  return -1;
 }
 const char *p = path;
 while (*p == '/')
  p++;
 if (*p == '\0') {
  close(dirfd);
  errno = EINVAL;
  return -1;
 }
 for (;;) {
  const char *slash = strchr(p, '/');
  size_t clen = slash ? (size_t)(slash - p) : strlen(p);
  if (clen == 0 || clen >= NAME_MAX ||
      (clen == 1 && p[0] == '.') ||
      (clen == 2 && p[0] == '.' && p[1] == '.')) {
   close(dirfd);
   errno = EINVAL;
   return -1;
  }
  char comp[NAME_MAX];
  memcpy(comp, p, clen);
  comp[clen] = '\0';
  if (slash) {
   while (*slash == '/')
    slash++;
   if (*slash == '\0') {
    close(dirfd);
    errno = EINVAL;
    return -1;
   }
   int nextfd = openat(dirfd, comp, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
   close(dirfd);
   if (nextfd < 0)
    return -1;
   if (fstat(nextfd, &dst) != 0 || !S_ISDIR(dst.st_mode) ||
       dst.st_uid != trusted_uid || (dst.st_mode & 022) != 0) {
    close(nextfd);
    errno = EPERM;
    return -1;
   }
   dirfd = nextfd;
   p = slash;
  } else {
   memcpy(leaf_out, comp, clen + 1);
   return dirfd;
  }
 }
}

static int csg_open_trusted_file_at(int root_fd, const char *path, uid_t trusted_uid)
{
 char leaf[NAME_MAX];
 int dirfd = csg_walk_parent_at(root_fd, path, trusted_uid, leaf);
 if (dirfd < 0)
  return -1;
 int fd = openat(dirfd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
 close(dirfd);
 if (fd < 0)
  return -1;
 struct stat st;
 if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
     st.st_uid != trusted_uid || (st.st_mode & 022) != 0 ||
     st.st_nlink != 1 || st.st_size <= 0 || st.st_size > 16 * 1024 * 1024) {
  close(fd);
  errno = EPERM;
  return -1;
 }
 return fd;
}

static int csg_read_trusted_snapshot_at(int root_fd, const char *path, uid_t trusted_uid,
                                        unsigned char **buf_out, size_t *len_out)
{
 *buf_out = NULL;
 *len_out = 0;
 int fd = csg_open_trusted_file_at(root_fd, path, trusted_uid);
 if (fd < 0)
  return -1;
 struct stat st0, st1;
 if (fstat(fd, &st0) != 0 || st0.st_size <= 0 || st0.st_size > 16 * 1024 * 1024) {
  close(fd);
  errno = EPERM;
  return -1;
 }
 size_t len = (size_t)st0.st_size, used = 0;
 unsigned char *buf = malloc(len + 1);
 if (!buf) {
  close(fd);
  return -1;
 }
 while (used < len) {
  ssize_t n = read(fd, buf + used, len - used);
  if (n < 0 && errno == EINTR)
   continue;
  if (n <= 0) {
   free(buf);
   close(fd);
   errno = EIO;
   return -1;
  }
  used += (size_t)n;
 }
 unsigned char extra = 0;
 ssize_t eof_rc;
 do {
  eof_rc = read(fd, &extra, 1);
 } while (eof_rc < 0 && errno == EINTR);
 if (eof_rc != 0 || fstat(fd, &st1) != 0 ||
     st1.st_dev != st0.st_dev || st1.st_ino != st0.st_ino ||
     st1.st_size != st0.st_size || st1.st_nlink != 1 ||
     st1.st_uid != trusted_uid || (st1.st_mode & 022) != 0 ||
     st1.st_mtime != st0.st_mtime || st1.st_ctime != st0.st_ctime) {
  free(buf);
  close(fd);
  errno = EIO;
  return -1;
 }
 close(fd);
 buf[len] = '\0';
 *buf_out = buf;
 *len_out = len;
 return 0;
}

static int csg_open_trusted_receipt_at(int root_fd, const char *path, uid_t trusted_uid)
{
 char leaf[NAME_MAX];
 int dirfd = csg_walk_parent_at(root_fd, path, trusted_uid, leaf);
 if (dirfd < 0)
  return -1;
 int fd = openat(dirfd, leaf,
                 O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
 close(dirfd);
 if (fd < 0)
  return -1;
 struct stat st;
 if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
     st.st_uid != trusted_uid || (st.st_mode & 077) != 0 ||
     st.st_nlink != 1 || st.st_size != 0) {
  close(fd);
  errno = EPERM;
  return -1;
 }
 return fd;
}

/* --- Bounded Async Receipt Writer with Deadline Drain & Hash Chain --- */
struct csg_receipt_writer {
 int             fd;
 int              (*sync_fn)(int);
 pthread_t       thread;
 pthread_mutex_t mtx;
 pthread_cond_t  not_empty;
 pthread_cond_t  not_full;
 pthread_cond_t  done_cond;
 char           *slots[CSG_RECEIPT_QUEUE_CAP];
 size_t          lengths[CSG_RECEIPT_QUEUE_CAP];
 unsigned        head;
 unsigned        tail;
 unsigned        count;
 unsigned        lost;
 int             io_error;
 bool            closing;
 bool            worker_done;
 bool            detached;
 bool            thread_started;
 uint64_t        seq;
 char            prev_sha256[CSG_SHA256_HEX_LEN + 1];
};

static void *csg_receipt_worker(void *arg)
{
 struct csg_receipt_writer *w = (struct csg_receipt_writer *)arg;
 sigset_t mask;
 sigemptyset(&mask);
 sigaddset(&mask, SIGINT);
 sigaddset(&mask, SIGTERM);
 sigaddset(&mask, SIGHUP);
 sigaddset(&mask, SIGPIPE);
 sigaddset(&mask, SIGQUIT);
 pthread_sigmask(SIG_BLOCK, &mask, NULL);

 for (;;) {
  pthread_mutex_lock(&w->mtx);
  while (w->count == 0 && !w->closing && w->io_error == 0) {
   pthread_cond_wait(&w->not_empty, &w->mtx);
  }
  if (w->count == 0 && (w->closing || w->io_error != 0)) {
   pthread_mutex_unlock(&w->mtx);
   break;
  }
  char *line = w->slots[w->head];
  size_t len = w->lengths[w->head];
  w->slots[w->head] = NULL;
  w->lengths[w->head] = 0;
  w->head = (w->head + 1u) % CSG_RECEIPT_QUEUE_CAP;
  w->count--;
  pthread_cond_signal(&w->not_full);
  pthread_mutex_unlock(&w->mtx);

  size_t off = 0;
  int err = 0;
  while (off < len) {
   ssize_t n = write(w->fd, line + off, len - off);
   if (n < 0 && errno == EINTR)
    continue;
   if (n <= 0) {
    err = errno ? errno : EIO;
    break;
   }
   off += (size_t)n;
  }
  free(line);
  if (err == 0) {
   int sync_rc = w->sync_fn ? w->sync_fn(w->fd) : fsync(w->fd);
   if (sync_rc != 0)
    err = errno ? errno : EIO;
  }
  if (err != 0) {
   pthread_mutex_lock(&w->mtx);
   if (w->io_error == 0)
    w->io_error = err;
   pthread_cond_broadcast(&w->not_full);
   pthread_mutex_unlock(&w->mtx);
   break;
  }
 }

 close(w->fd);
 pthread_mutex_lock(&w->mtx);
 while (w->count > 0) {
  free(w->slots[w->head]);
  w->slots[w->head] = NULL;
  w->head = (w->head + 1u) % CSG_RECEIPT_QUEUE_CAP;
  w->count--;
  w->lost++;
 }
 w->worker_done = true;
 bool self_free = w->detached;
 pthread_cond_broadcast(&w->done_cond);
 pthread_cond_broadcast(&w->not_full);
 pthread_mutex_unlock(&w->mtx);

 if (self_free) {
  pthread_cond_destroy(&w->not_empty);
  pthread_cond_destroy(&w->not_full);
  pthread_cond_destroy(&w->done_cond);
  pthread_mutex_destroy(&w->mtx);
  free(w);
 }
 return NULL;
}

static struct csg_receipt_writer *csg_receipt_create(int fd, int (*sync_fn)(int))
{
 struct csg_receipt_writer *w = calloc(1, sizeof(*w));
 if (!w)
  return NULL;
 w->fd = fd;
 w->sync_fn = sync_fn ? sync_fn : fsync;
 memset(w->prev_sha256, '0', CSG_SHA256_HEX_LEN);
 w->prev_sha256[CSG_SHA256_HEX_LEN] = '\0';

 if (pthread_mutex_init(&w->mtx, NULL) != 0) {
  free(w);
  return NULL;
 }
 pthread_condattr_t attr;
 if (pthread_condattr_init(&attr) != 0) {
  pthread_mutex_destroy(&w->mtx);
  free(w);
  return NULL;
 }
#ifdef __linux__
 pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
#endif
 if (pthread_cond_init(&w->not_empty, &attr) != 0 ||
     pthread_cond_init(&w->not_full, &attr) != 0 ||
     pthread_cond_init(&w->done_cond, &attr) != 0) {
  pthread_condattr_destroy(&attr);
  pthread_mutex_destroy(&w->mtx);
  free(w);
  return NULL;
 }
 pthread_condattr_destroy(&attr);

 if (pthread_create(&w->thread, NULL, csg_receipt_worker, w) != 0) {
  pthread_cond_destroy(&w->not_empty);
  pthread_cond_destroy(&w->not_full);
  pthread_cond_destroy(&w->done_cond);
  pthread_mutex_destroy(&w->mtx);
  free(w);
  return NULL;
 }
 w->thread_started = true;
 return w;
}

static void csg_json_escape(const char *src, char *dst, size_t cap)
{
 if (!dst || cap == 0) return;
 size_t w = 0;
 if (!src) {
  dst[0] = '\0';
  return;
 }
 for (size_t i = 0; src[i] != '\0'; i++) {
  unsigned char c = (unsigned char)src[i];
  const char *rep = NULL;
  switch (c) {
  case '"':  rep = "\\\""; break;
  case '\\': rep = "\\\\"; break;
  case '\n': rep = "\\n"; break;
  case '\r': rep = "\\r"; break;
  case '\t': rep = "\\t"; break;
  default: break;
  }
  if (rep) {
   size_t rlen = strlen(rep);
   if (w + rlen >= cap) break;
   memcpy(dst + w, rep, rlen);
   w += rlen;
  } else if (c >= 0x20u && c != 0x7fu) {
   if (w + 1 >= cap) break;
   dst[w++] = (char)c;
  }
 }
 dst[w] = '\0';
}

static bool csg_receipt_enqueue_raw(struct csg_receipt_writer *w, const char *event,
                                    const char *body_fields)
{
 pthread_mutex_lock(&w->mtx);
 if (w->closing || w->io_error != 0 || w->count >= CSG_RECEIPT_QUEUE_CAP) {
  w->lost++;
  pthread_mutex_unlock(&w->mtx);
  return false;
 }
 uint64_t seq = w->seq + 1u;
 uint64_t mono = csg_monotonic_ns();
 char prefix[CSG_RECEIPT_MAX_LINE];
 int n = snprintf(prefix, sizeof(prefix),
                  "{\"seq\":%llu,\"event\":\"%s\",\"monotonic_ns\":%llu%s%s,\"prev_sha256\":\"%s\"",
                  (unsigned long long)seq, event, (unsigned long long)mono,
                  (body_fields && body_fields[0]) ? "," : "",
                  (body_fields && body_fields[0]) ? body_fields : "",
                  w->prev_sha256);
 if (n < 0 || (size_t)n + 90u > CSG_RECEIPT_MAX_LINE) {
  w->lost++;
  pthread_mutex_unlock(&w->mtx);
  return false;
 }
 char entry_hash[CSG_SHA256_HEX_LEN + 1];
 csg_sha256_hex(prefix, (size_t)n, entry_hash);

 char full[CSG_RECEIPT_MAX_LINE + 1];
 int fn = snprintf(full, sizeof(full), "%s,\"entry_sha256\":\"%s\"}\n", prefix, entry_hash);
 if (fn < 0 || (size_t)fn > CSG_RECEIPT_MAX_LINE) {
  w->lost++;
  pthread_mutex_unlock(&w->mtx);
  return false;
 }
 char *copy = malloc((size_t)fn + 1u);
 if (!copy) {
  w->lost++;
  pthread_mutex_unlock(&w->mtx);
  return false;
 }
 memcpy(copy, full, (size_t)fn + 1u);
 w->seq = seq;
 memcpy(w->prev_sha256, entry_hash, CSG_SHA256_HEX_LEN + 1);
 w->slots[w->tail] = copy;
 w->lengths[w->tail] = (size_t)fn;
 w->tail = (w->tail + 1u) % CSG_RECEIPT_QUEUE_CAP;
 w->count++;
 pthread_cond_signal(&w->not_empty);
 pthread_mutex_unlock(&w->mtx);
 return true;
}

static bool csg_receipt_healthy(struct csg_receipt_writer *w)
{
 pthread_mutex_lock(&w->mtx);
 bool ok = (w->io_error == 0 && w->lost == 0);
 pthread_mutex_unlock(&w->mtx);
 return ok;
}

/* Fixes VULN-LAUNCH-004: waits up to timeout_ms on not_full before setting
 * closing = true, then waits up to the remaining deadline for worker_done.
 * Heap ownership is transferred to worker if detached on timeout. */
static bool csg_receipt_close(struct csg_receipt_writer *w, unsigned timeout_ms)
{
 if (!w || !w->thread_started)
  return false;
 struct timespec deadline;
 csg_Wait_deadline(&deadline, timeout_ms);

 pthread_mutex_lock(&w->mtx);
 while (w->count >= CSG_RECEIPT_QUEUE_CAP && !w->worker_done && w->io_error == 0) {
  if (pthread_cond_timedwait(&w->not_full, &w->mtx, &deadline) == ETIMEDOUT)
   break;
 }
 if (w->count >= CSG_RECEIPT_QUEUE_CAP && !w->worker_done)
  w->lost++;
 w->closing = true;
 pthread_cond_broadcast(&w->not_empty);

 while (!w->worker_done) {
  if (pthread_cond_timedwait(&w->done_cond, &w->mtx, &deadline) == ETIMEDOUT)
   break;
 }
 bool finished = w->worker_done;
 bool clean = finished && (w->io_error == 0) && (w->lost == 0);
 if (!finished) {
  w->detached = true;
  pthread_detach(w->thread);
 }
 pthread_mutex_unlock(&w->mtx);

 if (finished) {
  pthread_join(w->thread, NULL);
  pthread_cond_destroy(&w->not_empty);
  pthread_cond_destroy(&w->not_full);
  pthread_cond_destroy(&w->done_cond);
  pthread_mutex_destroy(&w->mtx);
  free(w);
 }
 return clean;
}

/* --- Runtime Operations Interface (Production + Deterministic Test Seam) --- */
struct csg_launch_ops {
 void    *ctx;
 uid_t    (*get_euid)(void *ctx);
 uid_t    trusted_uid;
 int      root_fd;
 int      (*get_release)(void *ctx, char *buf, size_t cap);
 int      (*set_no_new_privs)(void *ctx);
 int      (*run_cmd)(void *ctx, const char *const *argv, char *out, size_t cap);
 pid_t    (*spawn_vmm)(void *ctx, char *const *argv, uid_t uid, gid_t gid);
 int      (*poll_vmm)(void *ctx, pid_t pid, int *exit_code_out);
 int      (*kill_pg)(void *ctx, pid_t pgid, int sig);
 int      (*wait_vmm)(void *ctx, pid_t pid, unsigned timeout_ms, int *exit_code_out);
 int      (*fsync_fn)(int fd);
 void     (*sleep_seconds)(void *ctx, double seconds);
};

static uid_t prod_get_euid(void *ctx)
{
 (void)ctx;
 return geteuid();
}

static int prod_get_release(void *ctx, char *buf, size_t cap)
{
 (void)ctx;
 struct utsname u;
 if (uname(&u) != 0)
  return -1;
 size_t len = strlen(u.release);
 if (len + 1 > cap)
  return -1;
 memcpy(buf, u.release, len + 1);
 return 0;
}

static int prod_set_no_new_privs(void *ctx)
{
 (void)ctx;
#ifdef __linux__
 if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
  return -1;
 return 0;
#else
 return 0;
#endif
}

static void csg_close_extra_fds(int keep_fd)
{
 long max_fd = sysconf(_SC_OPEN_MAX);
 if (max_fd < 256 || max_fd > 65536)
  max_fd = 4096;
 for (int fd = 3; fd < (int)max_fd; fd++) {
  if (fd != keep_fd)
   (void)close(fd);
 }
}

static int prod_run_cmd(void *ctx, const char *const *argv, char *out, size_t cap)
{
 (void)ctx;
 if (out && cap > 0)
  out[0] = '\0';
 int pipefd[2];
 if (pipe(pipefd) != 0)
  return -1;
 pid_t pid = fork();
 if (pid < 0) {
  close(pipefd[0]);
  close(pipefd[1]);
  return -1;
 }
 if (pid == 0) {
  setsid();
  close(pipefd[0]);
  if (dup2(pipefd[1], STDOUT_FILENO) < 0)
   _exit(127);
  int devnull = open("/dev/null", O_RDWR);
  if (devnull >= 0) {
   dup2(devnull, STDIN_FILENO);
   dup2(devnull, STDERR_FILENO);
   if (devnull > 2)
    close(devnull);
  }
  close(pipefd[1]);
  csg_close_extra_fds(-1);
  char *const envp[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", NULL };
  execve(argv[0], (char *const *)(uintptr_t)argv, envp);
  _exit(127);
 }
 close(pipefd[1]);
 int flags = fcntl(pipefd[0], F_GETFL, 0);
 if (flags >= 0)
  fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

 uint64_t start_ns = csg_monotonic_ns();
 uint64_t limit_ns = 3000000000ull; /* 3 seconds */
 size_t used = 0;
 bool child_done = false;
 int status = 0;

 while (!child_done) {
  if (out && cap > 1 && used + 1 < cap) {
   ssize_t n = read(pipefd[0], out + used, cap - 1 - used);
   if (n > 0) {
    used += (size_t)n;
    out[used] = '\0';
   }
  } else {
   char discard[256];
   ssize_t nr = read(pipefd[0], discard, sizeof(discard));
   (void)nr;
  }
  pid_t w = waitpid(pid, &status, WNOHANG);
  if (w == pid) {
   child_done = true;
   break;
  }
  if (w < 0 && errno != EINTR) {
   close(pipefd[0]);
   return -1;
  }
  if (csg_monotonic_ns() - start_ns >= limit_ns) {
   kill(-pid, SIGKILL);
   kill(pid, SIGKILL);
   (void)waitpid(pid, &status, 0);
   close(pipefd[0]);
   errno = ETIMEDOUT;
   return -1;
  }
  struct timespec ts = { .tv_sec = 0, .tv_nsec = 5000000L };
  nanosleep(&ts, NULL);
 }
 /* Drain remaining pipe bytes */
 if (out && cap > 1) {
  for (;;) {
   if (used + 1 >= cap)
    break;
   ssize_t n = read(pipefd[0], out + used, cap - 1 - used);
   if (n > 0) {
    used += (size_t)n;
    out[used] = '\0';
   } else {
    break;
   }
  }
 }
 close(pipefd[0]);
 if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
  return -1;
 return 0;
}

static pid_t prod_spawn_vmm(void *ctx, char *const *argv, uid_t uid, gid_t gid)
{
 (void)ctx;
 pid_t pid = fork();
 if (pid < 0)
  return -1;
 if (pid == 0) {
  if (setsid() < 0)
   _exit(126);
  sigset_t empty;
  sigemptyset(&empty);
  sigprocmask(SIG_SETMASK, &empty, NULL);
  signal(SIGINT, SIG_DFL);
  signal(SIGTERM, SIG_DFL);
  signal(SIGHUP, SIG_DFL);
  signal(SIGPIPE, SIG_DFL);
  signal(SIGQUIT, SIG_DFL);
  umask(0077);
  csg_close_extra_fds(-1);
  if (chdir("/") != 0)
   _exit(126);
  if (setgroups(0, NULL) != 0)
   _exit(126);
#ifdef __linux__
  if (setresgid(gid, gid, gid) != 0 || getgid() != gid || getegid() != gid)
   _exit(126);
  if (setresuid(uid, uid, uid) != 0 || getuid() != uid || geteuid() != uid)
   _exit(126);
#else
  if (setgid(gid) != 0 || getgid() != gid || getegid() != gid)
   _exit(126);
  if (setuid(uid) != 0 || getuid() != uid || geteuid() != uid)
   _exit(126);
#endif
  /* Verify root privilege cannot be regained after irreversible drop. */
  if (setuid(0) == 0 || seteuid(0) == 0)
   _exit(126);
#ifdef __linux__
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
   _exit(126);
#endif
  char *const envp[] = { "PATH=/usr/bin:/bin", "LANG=C.UTF-8", NULL };
  execve(argv[0], argv, envp);
  _exit(127);
 }
 return pid;
}

static int prod_poll_vmm(void *ctx, pid_t pid, int *exit_code_out)
{
 (void)ctx;
 int status = 0;
 pid_t w = waitpid(pid, &status, WNOHANG);
 if (w == 0)
  return 0; /* still running */
 if (w < 0)
  return -1;
 if (WIFEXITED(status))
  *exit_code_out = WEXITSTATUS(status);
 else if (WIFSIGNALED(status))
  *exit_code_out = 128 + WTERMSIG(status);
 else
  *exit_code_out = 1;
 return 1; /* exited */
}

static int prod_kill_pg(void *ctx, pid_t pgid, int sig)
{
 (void)ctx;
 if (pgid <= 0)
  return -1;
 if (kill(-pgid, sig) != 0) {
  if (errno == ESRCH)
   return 0;
  return -1;
 }
 return 0;
}

static int prod_wait_vmm(void *ctx, pid_t pid, unsigned timeout_ms, int *exit_code_out)
{
 (void)ctx;
 uint64_t start_ns = csg_monotonic_ns();
 uint64_t limit_ns = (uint64_t)timeout_ms * 1000000ull;
 for (;;) {
  int status = 0;
  pid_t w = waitpid(pid, &status, WNOHANG);
  if (w == pid) {
   if (exit_code_out) {
    if (WIFEXITED(status))
     *exit_code_out = WEXITSTATUS(status);
    else
     *exit_code_out = 1;
   }
   return 0;
  }
  if (w < 0) {
   if (errno == ECHILD)
    return 0;
   if (errno != EINTR)
    return -1;
  }
  if (csg_monotonic_ns() - start_ns >= limit_ns) {
   errno = ETIMEDOUT;
   return -1;
  }
  struct timespec ts = { .tv_sec = 0, .tv_nsec = 5000000L };
  nanosleep(&ts, NULL);
 }
}

static void prod_sleep_seconds(void *ctx, double seconds)
{
 (void)ctx;
 if (seconds <= 0.0)
  return;
 time_t sec = (time_t)seconds;
 long nsec = (long)((seconds - (double)sec) * 1000000000.0);
 if (nsec < 0) nsec = 0;
 if (nsec >= 1000000000L) nsec = 999999999L;
 struct timespec ts = { .tv_sec = sec, .tv_nsec = nsec };
 nanosleep(&ts, NULL);
}

static int csg_parse_positive_id(const char *s, uint32_t *out)
{
 if (!s || s[0] < '1' || s[0] > '9')
  return -1;
 char *end = NULL;
 errno = 0;
 unsigned long v = strtoul(s, &end, 10);
 if (errno != 0 || !end || *end != '\0' || v == 0 || v > INT_MAX)
  return -1;
 *out = (uint32_t)v;
 return 0;
}

static int csg_parse_interval(const char *s, double *out)
{
 if (!s || !*s)
  return -1;
 char *end = NULL;
 errno = 0;
 double v = strtod(s, &end);
 if (errno != 0 || !end || *end != '\0' || !(v >= 0.05 && v <= 5.0))
  return -1;
 *out = v;
 return 0;
}

static int csg_call_status(const struct csg_launch_ops *ops, const char *loader,
                           const struct csg_identity *expected,
                           struct csg_identity *observed_out)
{
 char ifidx_str[32], netns_str[32], prog_str[32];
 snprintf(ifidx_str, sizeof(ifidx_str), "%u", expected->ifindex);
 snprintf(netns_str, sizeof(netns_str), "%llu", (unsigned long long)expected->netns_inode);
 snprintf(prog_str, sizeof(prog_str), "%u", expected->prog_id);
 const char *const argv[] = {
  loader, "status", expected->interface, ifidx_str, netns_str, prog_str, NULL
 };
 char out[4096];
 if (ops->run_cmd(ops->ctx, argv, out, sizeof(out)) != 0)
  return -1;
 return csg_parse_identity_json(out, strlen(out), observed_out);
}

static int csg_disconnect_iface(const struct csg_launch_ops *ops,
                                const struct csg_identity *identity,
                                char *err_buf, size_t err_cap)
{
 const char *const show_argv[] = {
  "/usr/sbin/ip", "-j", "link", "show", "dev", identity->interface, NULL
 };
 char out[4096];
 if (ops->run_cmd(ops->ctx, show_argv, out, sizeof(out)) != 0) {
  snprintf(err_buf, err_cap, "ip link show failed for %s", identity->interface);
  return -1;
 }
 uint32_t cur_ifindex = 0;
 if (csg_parse_ip_link_ifindex(out, strlen(out), &cur_ifindex) != 0) {
  snprintf(err_buf, err_cap, "ambiguous or malformed ip link output");
  return -1;
 }
 if (cur_ifindex != identity->ifindex) {
  snprintf(err_buf, err_cap, "interface identity changed; refusing to mutate replacement");
  return -1;
 }
 const char *const down_argv[] = {
  "/usr/sbin/ip", "link", "set", "dev", identity->interface, "down", NULL
 };
 if (ops->run_cmd(ops->ctx, down_argv, out, sizeof(out)) != 0) {
  snprintf(err_buf, err_cap, "ip link set dev %s down failed", identity->interface);
  return -1;
 }
 return 0;
}

static int csg_launch_run(int argc, char **argv, const struct csg_launch_ops *custom_ops,
                          char *err_msg, size_t err_cap)
{
 if (err_msg && err_cap > 0)
  err_msg[0] = '\0';

 int default_root_fd = -1;
 struct csg_launch_ops ops;
 if (custom_ops) {
  ops = *custom_ops;
 } else {
  default_root_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (default_root_fd < 0) {
   snprintf(err_msg, err_cap, "failed to open root directory");
   return 1;
  }
  memset(&ops, 0, sizeof(ops));
  ops.get_euid          = prod_get_euid;
  ops.trusted_uid       = 0;
  ops.root_fd           = default_root_fd;
  ops.get_release       = prod_get_release;
  ops.set_no_new_privs  = prod_set_no_new_privs;
  ops.run_cmd           = prod_run_cmd;
  ops.spawn_vmm         = prod_spawn_vmm;
  ops.poll_vmm          = prod_poll_vmm;
  ops.kill_pg           = prod_kill_pg;
  ops.wait_vmm          = prod_wait_vmm;
  ops.fsync_fn          = fsync;
  ops.sleep_seconds     = prod_sleep_seconds;
 }

 const char *iface = NULL;
 const char *loader_path = NULL;
 const char *object_path = NULL;
 const char *evidence_path = NULL;
 const char *receipt_path = NULL;
 uint32_t uid_val = 0, gid_val = 0;
 bool has_uid = false, has_gid = false;
 double interval = 0.2;
 int cmd_start = -1;

 for (int i = 1; i < argc; i++) {
  if (strcmp(argv[i], "--") == 0) {
   cmd_start = i + 1;
   break;
  }
  if (argv[i][0] != '-') {
   cmd_start = i;
   break;
  }
  if (i + 1 >= argc) {
   snprintf(err_msg, err_cap, "missing value for option %s", argv[i]);
   if (default_root_fd >= 0) close(default_root_fd);
   return 2;
  }
  const char *opt = argv[i];
  const char *val = argv[++i];
  if (strcmp(opt, "--interface") == 0) {
   iface = val;
  } else if (strcmp(opt, "--loader") == 0) {
   loader_path = val;
  } else if (strcmp(opt, "--object") == 0) {
   object_path = val;
  } else if (strcmp(opt, "--evidence") == 0) {
   evidence_path = val;
  } else if (strcmp(opt, "--receipt") == 0) {
   receipt_path = val;
  } else if (strcmp(opt, "--uid") == 0) {
   if (csg_parse_positive_id(val, &uid_val) != 0) {
    snprintf(err_msg, err_cap, "invalid --uid");
    if (default_root_fd >= 0) close(default_root_fd);
    return 2;
   }
   has_uid = true;
  } else if (strcmp(opt, "--gid") == 0) {
   if (csg_parse_positive_id(val, &gid_val) != 0) {
    snprintf(err_msg, err_cap, "invalid --gid");
    if (default_root_fd >= 0) close(default_root_fd);
    return 2;
   }
   has_gid = true;
  } else if (strcmp(opt, "--interval") == 0) {
   if (csg_parse_interval(val, &interval) != 0) {
    snprintf(err_msg, err_cap, "interval must be 0.05..5 seconds");
    if (default_root_fd >= 0) close(default_root_fd);
    return 2;
   }
  } else {
   snprintf(err_msg, err_cap, "unknown option %s", opt);
   if (default_root_fd >= 0) close(default_root_fd);
   return 2;
  }
 }

 if (!iface || !csg_valid_ifname(iface) || !loader_path || !object_path ||
     !evidence_path || !receipt_path || !has_uid || !has_gid ||
     cmd_start < 0 || cmd_start >= argc || !argv[cmd_start] ||
     argv[cmd_start][0] != '/') {
  snprintf(err_msg, err_cap, "root supervisor, nonzero guest UID/GID and absolute VMM command required");
  if (default_root_fd >= 0) close(default_root_fd);
  return 2;
 }
 if (ops.get_euid(ops.ctx) != 0) {
  snprintf(err_msg, err_cap, "root supervisor required");
  if (default_root_fd >= 0) close(default_root_fd);
  return 2;
 }

 /* Verify loader binary, BPF object snapshot, and admission evidence snapshot */
 int loader_fd = csg_open_trusted_file_at(ops.root_fd, loader_path, ops.trusted_uid);
 if (loader_fd < 0) {
  snprintf(err_msg, err_cap, "untrusted or missing loader binary");
  if (default_root_fd >= 0) close(default_root_fd);
  return 1;
 }
 close(loader_fd);

 unsigned char *obj_bytes = NULL;
 size_t obj_len = 0;
 if (csg_read_trusted_snapshot_at(ops.root_fd, object_path, ops.trusted_uid,
                                  &obj_bytes, &obj_len) != 0) {
  snprintf(err_msg, err_cap, "untrusted or unreadable BPF object");
  if (default_root_fd >= 0) close(default_root_fd);
  return 1;
 }
 char obj_sha256[CSG_SHA256_HEX_LEN + 1];
 csg_sha256_hex(obj_bytes, obj_len, obj_sha256);
 free(obj_bytes);

 unsigned char *ev_bytes = NULL;
 size_t ev_len = 0;
 if (csg_read_trusted_snapshot_at(ops.root_fd, evidence_path, ops.trusted_uid,
                                  &ev_bytes, &ev_len) != 0) {
  snprintf(err_msg, err_cap, "untrusted or unreadable admission evidence");
  if (default_root_fd >= 0) close(default_root_fd);
  return 1;
 }
 char ev_sha256[CSG_SHA256_HEX_LEN + 1];
 csg_sha256_hex(ev_bytes, ev_len, ev_sha256);

 struct csg_evidence evidence;
 if (csg_parse_evidence_json((const char *)ev_bytes, ev_len, &evidence) != 0) {
  free(ev_bytes);
  snprintf(err_msg, err_cap, "malformed admission evidence JSON");
  if (default_root_fd >= 0) close(default_root_fd);
  return 1;
 }
 free(ev_bytes);

 char release[CSG_MAX_STR_LEN];
 if (ops.get_release(ops.ctx, release, sizeof(release)) != 0) {
  snprintf(err_msg, err_cap, "unable to determine running kernel release");
  if (default_root_fd >= 0) close(default_root_fd);
  return 1;
 }
 if (csg_validate_evidence(&evidence, release, obj_sha256) != 0) {
  snprintf(err_msg, err_cap, "admission evidence rejected");
  if (default_root_fd >= 0) close(default_root_fd);
  return 1;
 }

 int receipt_fd = csg_open_trusted_receipt_at(ops.root_fd, receipt_path, ops.trusted_uid);
 if (receipt_fd < 0) {
  snprintf(err_msg, err_cap, "failed to create exclusive receipt in trusted directory");
  if (default_root_fd >= 0) close(default_root_fd);
  return 1;
 }
 if (default_root_fd >= 0) {
  close(default_root_fd);
  default_root_fd = -1;
 }

 if (ops.set_no_new_privs(ops.ctx) != 0) {
  close(receipt_fd);
  snprintf(err_msg, err_cap, "PR_SET_NO_NEW_PRIVS failed");
  return 1;
 }

 struct csg_receipt_writer *writer = csg_receipt_create(receipt_fd, ops.fsync_fn);
 if (!writer) {
  close(receipt_fd);
  snprintf(err_msg, err_cap, "failed to start receipt writer thread");
  return 1;
 }

 g_stop_signal = 0;
 struct sigaction sa;
 memset(&sa, 0, sizeof(sa));
 sa.sa_handler = csg_signal_handler;
 sigemptyset(&sa.sa_mask);
 sigaction(SIGINT, &sa, NULL);
 sigaction(SIGTERM, &sa, NULL);
 sigaction(SIGHUP, &sa, NULL);

 bool has_identity = false;
 struct csg_identity identity;
 memset(&identity, 0, sizeof(identity));
 struct csg_lifecycle lifecycle;
 memset(&lifecycle, 0, sizeof(lifecycle));
 lifecycle.state.evidence = CSG_EVIDENCE_VERIFIED;
 pid_t vmm_pid = -1;
 int exit_code = 1;
 bool quarantined = false;
 char quarantine_reason[256] = "";

 char rel_esc[256];
 csg_json_escape(release, rel_esc, sizeof(rel_esc));
 char body[1024];
 snprintf(body, sizeof(body),
          "\"running_kernel\":\"%s\",\"guard_sha256\":\"%s\",\"evidence_sha256\":\"%s\","
          "\"assurance\":\"operator-attested; target validation remains external\"",
          rel_esc, obj_sha256, ev_sha256);
 csg_receipt_enqueue_raw(writer, "operator_evidence_accepted", body);

 if (g_stop_signal != 0) {
  csg_lifecycle_fault(&lifecycle, CSG_PRESENCE_EMPTY,
                      CSG_VALENCE_NEGATIVE, CSG_COHERENCE_PARTIAL);
  snprintf(quarantine_reason, sizeof(quarantine_reason),
           "supervisor interrupted: %d", (int)g_stop_signal);
  quarantined = true;
  goto contain;
 }

 /* Step 1: Attach TC BPF guard via loader */
 const char *const attach_argv[] = {
  loader_path, "attach", iface, object_path, obj_sha256, NULL
 };
 char cmd_out[4096];
 if (ops.run_cmd(ops.ctx, attach_argv, cmd_out, sizeof(cmd_out)) != 0 ||
     csg_parse_identity_json(cmd_out, strlen(cmd_out), &identity) != 0 ||
     strcmp(identity.interface, iface) != 0) {
  csg_lifecycle_fault(&lifecycle, CSG_PRESENCE_UNKNOWN,
                      CSG_VALENCE_NEGATIVE, CSG_COHERENCE_DECOHERENT);
  snprintf(quarantine_reason, sizeof(quarantine_reason), "loader attach failed");
  quarantined = true;
  goto contain;
 }
 has_identity = true;
 if (csg_lifecycle_init(&lifecycle, &identity) != 0) {
  csg_lifecycle_fault(&lifecycle, CSG_PRESENCE_PRESENT,
                      CSG_VALENCE_ANTI, CSG_COHERENCE_DECOHERENT);
  snprintf(quarantine_reason, sizeof(quarantine_reason), "invalid attachment identity");
  quarantined = true;
  goto contain;
 }

 if (g_stop_signal != 0) {
  csg_lifecycle_fault(&lifecycle, lifecycle.state.presence,
                      CSG_VALENCE_NEGATIVE, CSG_COHERENCE_PARTIAL);
  snprintf(quarantine_reason, sizeof(quarantine_reason),
           "supervisor interrupted: %d", (int)g_stop_signal);
  quarantined = true;
  goto contain;
 }

 /* Step 2: Verify status while still DOWN */
 struct csg_identity observed;
 const struct csg_identity *pre_obs = NULL;
 if (csg_call_status(&ops, loader_path, &identity, &observed) == 0)
  pre_obs = &observed;
 if (csg_lifecycle_ready(&lifecycle, pre_obs) != CSG_DECISION_ADMIT) {
  snprintf(quarantine_reason, sizeof(quarantine_reason), "admission identity mismatch");
  quarantined = true;
  goto contain;
 }

 if (g_stop_signal != 0) {
  csg_lifecycle_fault(&lifecycle, lifecycle.state.presence,
                      CSG_VALENCE_NEGATIVE, CSG_COHERENCE_PARTIAL);
  snprintf(quarantine_reason, sizeof(quarantine_reason),
           "supervisor interrupted: %d", (int)g_stop_signal);
  quarantined = true;
  goto contain;
 }

 /* Step 3: Bring interface UP */
 const char *const up_argv[] = {
  "/usr/sbin/ip", "link", "set", "dev", iface, "up", NULL
 };
 if (ops.run_cmd(ops.ctx, up_argv, cmd_out, sizeof(cmd_out)) != 0) {
  csg_lifecycle_fault(&lifecycle, lifecycle.state.presence,
                      CSG_VALENCE_NEGATIVE, CSG_COHERENCE_PARTIAL);
  snprintf(quarantine_reason, sizeof(quarantine_reason), "ip link set up failed");
  quarantined = true;
  goto contain;
 }

 /* Step 4: Recheck attachment identity after enabling interface, before VMM spawn */
 const struct csg_identity *post_obs = NULL;
 if (csg_call_status(&ops, loader_path, &identity, &observed) == 0)
  post_obs = &observed;
 if (csg_lifecycle_ready(&lifecycle, post_obs) != CSG_DECISION_ADMIT) {
  snprintf(quarantine_reason, sizeof(quarantine_reason), "attachment lost before launch");
  quarantined = true;
  goto contain;
 }

 if (g_stop_signal != 0) {
  csg_lifecycle_fault(&lifecycle, lifecycle.state.presence,
                      CSG_VALENCE_NEGATIVE, CSG_COHERENCE_PARTIAL);
  snprintf(quarantine_reason, sizeof(quarantine_reason),
           "supervisor interrupted: %d", (int)g_stop_signal);
  quarantined = true;
  goto contain;
 }

 /* Step 5: Spawn non-root VMM in dedicated session / process group */
 vmm_pid = ops.spawn_vmm(ops.ctx, &argv[cmd_start], (uid_t)uid_val, (gid_t)gid_val);
 if (vmm_pid <= 0) {
  csg_lifecycle_fault(&lifecycle, lifecycle.state.presence,
                      CSG_VALENCE_NEGATIVE, CSG_COHERENCE_PARTIAL);
  snprintf(quarantine_reason, sizeof(quarantine_reason), "failed to spawn VMM");
  quarantined = true;
  goto contain;
 }
 if (csg_lifecycle_started(&lifecycle) != CSG_DECISION_ADMIT) {
  csg_lifecycle_fault(&lifecycle, lifecycle.state.presence,
                      CSG_VALENCE_ANTI, CSG_COHERENCE_DECOHERENT);
  snprintf(quarantine_reason, sizeof(quarantine_reason), "cannot launch before admission");
  quarantined = true;
  goto contain;
 }
 snprintf(body, sizeof(body),
          "\"identity\":{\"interface\":\"%s\",\"ifindex\":%u,\"netns_inode\":%llu,\"prog_id\":%u},"
          "\"pid\":%d,\"uid\":%u,\"gid\":%u",
          identity.interface, identity.ifindex,
          (unsigned long long)identity.netns_inode, identity.prog_id,
          (int)vmm_pid, uid_val, gid_val);
 csg_receipt_enqueue_raw(writer, "launched", body);

 /* Step 6: Supervision Loop */
 for (;;) {
  if (g_stop_signal != 0) {
   csg_lifecycle_fault(&lifecycle, lifecycle.state.presence,
                       CSG_VALENCE_NEGATIVE, CSG_COHERENCE_PARTIAL);
   snprintf(quarantine_reason, sizeof(quarantine_reason),
            "supervisor interrupted: %d", (int)g_stop_signal);
   quarantined = true;
   goto contain;
  }
  int child_rc = 0;
  int poll_st = ops.poll_vmm(ops.ctx, vmm_pid, &child_rc);
  if (poll_st < 0) {
   csg_lifecycle_fault(&lifecycle, lifecycle.state.presence,
                       CSG_VALENCE_NEGATIVE, CSG_COHERENCE_PARTIAL);
   snprintf(quarantine_reason, sizeof(quarantine_reason), "waitpid poll failed");
   quarantined = true;
   goto contain;
  }
  if (poll_st > 0) {
   lifecycle.state.lifecycle = CSG_LIFECYCLE_EXITED;
   lifecycle.state.epoch++;
   snprintf(body, sizeof(body), "\"returncode\":%d", child_rc);
   csg_receipt_enqueue_raw(writer, "exited", body);
   exit_code = (child_rc >= 0 && child_rc <= 125) ? child_rc : 1;
   break;
  }

  struct csg_identity poll_obs;
  const struct csg_identity *obs_ptr = NULL;
  if (csg_call_status(&ops, loader_path, &identity, &poll_obs) == 0)
   obs_ptr = &poll_obs;

  if (!csg_receipt_healthy(writer)) {
   lifecycle.state.evidence = CSG_EVIDENCE_OVERFLOWED;
   csg_lifecycle_fault(&lifecycle, lifecycle.state.presence,
                       CSG_VALENCE_NEGATIVE, CSG_COHERENCE_PARTIAL);
   snprintf(quarantine_reason, sizeof(quarantine_reason),
            "receipt writer failed or overflowed");
   quarantined = true;
   goto contain;
  }
  if (csg_lifecycle_observe(&lifecycle, obs_ptr) != CSG_DECISION_ADMIT) {
   snprintf(quarantine_reason, sizeof(quarantine_reason),
            "protection identity lost");
   quarantined = true;
   goto contain;
  }
  ops.sleep_seconds(ops.ctx, interval);
 }

contain:
 /* Block SIGINT/SIGTERM/SIGHUP so teardown and quarantine cannot be aborted
  * by signal re-entrancy (Fixes VULN-LAUNCH-001). */
 {
  sigset_t block_set;
  sigemptyset(&block_set);
  sigaddset(&block_set, SIGINT);
  sigaddset(&block_set, SIGTERM);
  sigaddset(&block_set, SIGHUP);
  pthread_sigmask(SIG_BLOCK, &block_set, NULL);
 }

 if (quarantined) {
  exit_code = 1;
  /* Fixes VULN-LAUNCH-003: Unconditionally signal the entire VMM process group
   * (-vmm_pid) regardless of whether the session leader has already exited. */
  if (vmm_pid > 0)
   (void)ops.kill_pg(ops.ctx, vmm_pid, SIGSTOP);
  if (has_identity) {
   char disc_err[256] = "";
   if (csg_disconnect_iface(&ops, &identity, disc_err, sizeof(disc_err)) != 0) {
    char esc_err[384];
    csg_json_escape(disc_err, esc_err, sizeof(esc_err));
    snprintf(body, sizeof(body), "\"error\":\"%s\"", esc_err);
    csg_receipt_enqueue_raw(writer, "disconnect_failed", body);
   }
  }
  if (vmm_pid > 0) {
   (void)ops.kill_pg(ops.ctx, vmm_pid, SIGKILL);
   (void)ops.wait_vmm(ops.ctx, vmm_pid, 3000, NULL);
  }
  char esc_reason[384];
  csg_json_escape(quarantine_reason, esc_reason, sizeof(esc_reason));
  snprintf(body, sizeof(body),
           "\"error\":\"%s\",\"vector_state\":{\"presence\":\"%s\",\"valence\":\"%s\","
           "\"coherence\":\"%s\",\"evidence\":\"%s\",\"lifecycle\":\"%s\",\"epoch\":%llu}",
           esc_reason,
           csg_presence_str(lifecycle.state.presence),
           csg_valence_str(lifecycle.state.valence),
           csg_coherence_str(lifecycle.state.coherence),
           csg_evidence_status_str(lifecycle.state.evidence),
           csg_lifecycle_str(lifecycle.state.lifecycle),
           (unsigned long long)lifecycle.state.epoch);
  csg_receipt_enqueue_raw(writer, "denied_or_quarantined", body);
  snprintf(err_msg, err_cap, "%s", quarantine_reason);
 }

 /* Final teardown on normal exit: ensure interface is brought DOWN.
  * Fixes VULN-LAUNCH-002: if cleanup disconnect fails, record
  * cleanup_disconnect_failed AND force exit_code = 1. */
 if (has_identity && !quarantined) {
  char disc_err[256] = "";
  if (csg_disconnect_iface(&ops, &identity, disc_err, sizeof(disc_err)) != 0) {
   char esc_err[384];
   csg_json_escape(disc_err, esc_err, sizeof(esc_err));
   snprintf(body, sizeof(body), "\"error\":\"%s\"", esc_err);
   csg_receipt_enqueue_raw(writer, "cleanup_disconnect_failed", body);
   exit_code = 1;
   if (err_msg && err_cap > 0 && err_msg[0] == '\0')
    snprintf(err_msg, err_cap, "%s", disc_err);
  }
 }

 /* Keep the guard attached. Never restore an unrestricted fallback. */
 if (!csg_receipt_close(writer, 200)) {
  exit_code = 1;
  snprintf(err_msg, err_cap, "receipt incomplete; no assurance claim permitted");
 }
 return exit_code;
}

#ifndef CSG_LAUNCH_LIBRARY
int main(int argc, char **argv)
{
 char err[512] = "";
 int rc = csg_launch_run(argc, argv, NULL, err, sizeof(err));
 if (rc != 0) {
  fprintf(stderr, "csumguard launch denied: %s\n",
          err[0] ? err : "execution failed");
  return 1;
 }
 return 0;
}
#endif
