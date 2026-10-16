/* SPDX-License-Identifier: GPL-2.0 */
#define CSG_LAUNCH_LIBRARY 1
#include "../launch.c"
#include <assert.h>

static unsigned g_tests_passed = 0;

/* --- 1. Pure Semantic Kernel & Vector State Unit Tests --- */
static void test_sha256_fips_vectors(void)
{
 char hex[65];
 csg_sha256_hex("", 0, hex);
 assert(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
 csg_sha256_hex("abc", 3, hex);
 assert(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
 const char *msg56 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
 csg_sha256_hex(msg56, strlen(msg56), hex);
 assert(strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0);
 g_tests_passed++;
}

static struct csg_evidence valid_evidence_fixture(const char *digest)
{
 struct csg_evidence ev;
 memset(&ev, 0, sizeof(ev));
 strcpy(ev.schema_version, "csumguard-admission/v1");
 strcpy(ev.running_kernel, "test");
 strcpy(ev.guard_sha256, digest);
 strcpy(ev.kernel_package, "test-package");
 strcpy(ev.fix_reference, "backport-record");
 strcpy(ev.validation_receipt, "lab-receipt");
 ev.kernel_patch_verified      = true;
 ev.network_path_validated     = true;
 ev.backend_metadata_validated = true;
 ev.compatibility_validated    = true;
 ev.exclusive_tc_owner         = true;
 ev.has_schema_version             = true;
 ev.has_running_kernel             = true;
 ev.has_guard_sha256               = true;
 ev.has_kernel_package             = true;
 ev.has_fix_reference              = true;
 ev.has_validation_receipt         = true;
 ev.has_kernel_patch_verified      = true;
 ev.has_network_path_validated     = true;
 ev.has_backend_metadata_validated = true;
 ev.has_compatibility_validated    = true;
 ev.has_exclusive_tc_owner         = true;
 return ev;
}

static struct csg_identity valid_identity_fixture(void)
{
 struct csg_identity id;
 memset(&id, 0, sizeof(id));
 strcpy(id.interface, "tap01");
 id.ifindex         = 5;
 id.netns_inode     = 999;
 id.prog_id         = 88;
 id.has_interface   = true;
 id.has_ifindex     = true;
 id.has_netns_inode = true;
 id.has_prog_id     = true;
 return id;
}

static void test_valid_evidence(void)
{
 const char *digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
 struct csg_evidence ev = valid_evidence_fixture(digest);
 assert(csg_validate_evidence(&ev, "test", digest) == 0);
 g_tests_passed++;
}

static void test_every_missing_appraisal_denies(void)
{
 const char *digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
 static const char *const bad_vals[4] = { "false", "null", "\"true\"", "1" };

 for (size_t k = 0; k < 5; k++) {
  for (size_t v = 0; v < 4; v++) {
   char json[1024];
   snprintf(json, sizeof(json),
            "{\"schema_version\":\"csumguard-admission/v1\","
            "\"running_kernel\":\"test\","
            "\"guard_sha256\":\"%s\","
            "\"kernel_package\":\"pkg\","
            "\"fix_reference\":\"ref\","
            "\"validation_receipt\":\"rcpt\","
            "\"kernel_patch_verified\":%s,"
            "\"network_path_validated\":%s,"
            "\"backend_metadata_validated\":%s,"
            "\"compatibility_validated\":%s,"
            "\"exclusive_tc_owner\":%s}",
            digest,
            k == 0 ? bad_vals[v] : "true",
            k == 1 ? bad_vals[v] : "true",
            k == 2 ? bad_vals[v] : "true",
            k == 3 ? bad_vals[v] : "true",
            k == 4 ? bad_vals[v] : "true");
   struct csg_evidence parsed;
   int prc = csg_parse_evidence_json(json, strlen(json), &parsed);
   if (prc == 0) {
    assert(csg_validate_evidence(&parsed, "test", digest) != 0);
   }
  }
 }
 g_tests_passed++;
}

static void test_identity_mismatch_denies(void)
{
 const char *digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
 struct csg_evidence ev = valid_evidence_fixture(digest);
 strcpy(ev.running_kernel, "changed");
 assert(csg_validate_evidence(&ev, "test", digest) != 0);

 ev = valid_evidence_fixture(digest);
 strcpy(ev.guard_sha256, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
 assert(csg_validate_evidence(&ev, "test", digest) != 0);

 ev = valid_evidence_fixture(digest);
 strcpy(ev.schema_version, "changed");
 assert(csg_validate_evidence(&ev, "test", digest) != 0);
 g_tests_passed++;
}

static void test_evidence_references_required(void)
{
 const char *digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
 struct csg_evidence ev = valid_evidence_fixture(digest);
 ev.kernel_package[0] = '\0';
 assert(csg_validate_evidence(&ev, "test", digest) != 0);

 ev = valid_evidence_fixture(digest);
 strcpy(ev.fix_reference, "   ");
 assert(csg_validate_evidence(&ev, "test", digest) != 0);

 ev = valid_evidence_fixture(digest);
 ev.validation_receipt[0] = '\0';
 assert(csg_validate_evidence(&ev, "test", digest) != 0);
 g_tests_passed++;
}

static void test_no_launch_before_ready(void)
{
 struct csg_identity id = valid_identity_fixture();
 struct csg_lifecycle lc;
 assert(csg_lifecycle_init(&lc, &id) == 0);
 assert(csg_lifecycle_started(&lc) == CSG_DECISION_DENY);
 g_tests_passed++;
}

static void test_ready_mismatch_denies(void)
{
 struct csg_identity id = valid_identity_fixture();
 struct csg_identity bad = id;
 bad.ifindex = 6;
 struct csg_lifecycle lc;
 assert(csg_lifecycle_init(&lc, &id) == 0);
 assert(csg_lifecycle_ready(&lc, &bad) == CSG_DECISION_DENY);
 assert(lc.state.valence == CSG_VALENCE_ANTI);
 assert(lc.state.coherence == CSG_COHERENCE_DECOHERENT);
 assert(lc.state.lifecycle == CSG_LIFECYCLE_QUARANTINED);
 g_tests_passed++;
}

static void test_valid_lifecycle(void)
{
 struct csg_identity id = valid_identity_fixture();
 struct csg_lifecycle lc;
 assert(csg_lifecycle_init(&lc, &id) == 0);
 assert(csg_lifecycle_ready(&lc, &id) == CSG_DECISION_ADMIT);
 assert(csg_lifecycle_started(&lc) == CSG_DECISION_ADMIT);
 assert(csg_lifecycle_observe(&lc, &id) == CSG_DECISION_ADMIT);
 assert(lc.state.lifecycle == CSG_LIFECYCLE_RUNNING);
 assert(lc.state.presence == CSG_PRESENCE_PRESENT);
 assert(lc.state.valence == CSG_VALENCE_POSITIVE);
 assert(lc.state.coherence == CSG_COHERENCE_COHERENT);
 g_tests_passed++;
}

static void test_each_identity_loss_quarantines(void)
{
 struct csg_identity id = valid_identity_fixture();
 for (int field = 0; field < 4; field++) {
  struct csg_lifecycle lc;
  assert(csg_lifecycle_init(&lc, &id) == 0);
  assert(csg_lifecycle_ready(&lc, &id) == CSG_DECISION_ADMIT);
  assert(csg_lifecycle_started(&lc) == CSG_DECISION_ADMIT);
  struct csg_identity mutated = id;
  if (field == 0) strcpy(mutated.interface, "tap02");
  if (field == 1) mutated.ifindex = 6;
  if (field == 2) mutated.netns_inode = 1000;
  if (field == 3) mutated.prog_id = 89;
  assert(csg_lifecycle_observe(&lc, &mutated) == CSG_DECISION_QUARANTINE);
  assert(lc.state.lifecycle == CSG_LIFECYCLE_QUARANTINED);
  assert(lc.state.presence == CSG_PRESENCE_PRESENT);
  assert(lc.state.valence == CSG_VALENCE_ANTI);
  assert(lc.state.coherence == CSG_COHERENCE_DECOHERENT);
 }
 g_tests_passed++;
}

static void test_missing_observation_quarantines(void)
{
 struct csg_identity id = valid_identity_fixture();
 struct csg_lifecycle lc;
 assert(csg_lifecycle_init(&lc, &id) == 0);
 assert(csg_lifecycle_ready(&lc, &id) == CSG_DECISION_ADMIT);
 assert(csg_lifecycle_started(&lc) == CSG_DECISION_ADMIT);
 assert(csg_lifecycle_observe(&lc, NULL) == CSG_DECISION_QUARANTINE);
 assert(lc.state.lifecycle == CSG_LIFECYCLE_QUARANTINED);
 /* VULN-LAUNCH-006: Missing observation must record UNKNOWN presence, not ANTI */
 assert(lc.state.presence == CSG_PRESENCE_UNKNOWN);
 assert(lc.state.valence == CSG_VALENCE_NEUTRAL);
 assert(lc.state.coherence == CSG_COHERENCE_DECOHERENT);
 g_tests_passed++;
}

static void test_invalid_identity_denies(void)
{
 /* VULN-LAUNCH-005 regression: missing or empty interface in both structs must fail */
 struct csg_identity a = valid_identity_fixture();
 struct csg_identity b = valid_identity_fixture();
 a.interface[0] = '\0';
 b.interface[0] = '\0';
 assert(!csg_same_identity(&a, &b));

 a = valid_identity_fixture();
 b = valid_identity_fixture();
 a.has_interface = false;
 b.has_interface = false;
 assert(!csg_same_identity(&a, &b));

 a = valid_identity_fixture();
 b = valid_identity_fixture();
 strcpy(a.interface, "../tap0");
 strcpy(b.interface, "../tap0");
 assert(!csg_same_identity(&a, &b));

 static const char *const bad_jsons[] = {
  "{\"interface\":\"tap01\",\"ifindex\":true,\"netns_inode\":999,\"prog_id\":88}",
  "{\"interface\":\"tap01\",\"ifindex\":0,\"netns_inode\":999,\"prog_id\":88}",
  "{\"interface\":\"tap01\",\"ifindex\":-1,\"netns_inode\":999,\"prog_id\":88}",
  "{\"interface\":\"tap01\",\"ifindex\":\"5\",\"netns_inode\":999,\"prog_id\":88}",
  "{\"interface\":\"tap01\",\"ifindex\":null,\"netns_inode\":999,\"prog_id\":88}",
  "{\"interface\":\"\",\"ifindex\":5,\"netns_inode\":999,\"prog_id\":88}",
  "{\"ifindex\":5,\"netns_inode\":999,\"prog_id\":88}"
 };
 for (size_t i = 0; i < sizeof(bad_jsons) / sizeof(bad_jsons[0]); i++) {
  struct csg_identity parsed;
  assert(csg_parse_identity_json(bad_jsons[i], strlen(bad_jsons[i]), &parsed) != 0);
 }
 g_tests_passed++;
}

/* --- 2. Filesystem Trust & Receipt Queue Regression Tests --- */
static void test_trusted_filesystem_checks(void)
{
 char tmpl[] = "/tmp/csg-fs-test-XXXXXX";
 char *root = mkdtemp(tmpl);
 assert(root != NULL);
 assert(chmod(root, 0700) == 0);
 int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
 assert(root_fd >= 0);
 uid_t my_uid = geteuid();

 /* Valid regular file */
 char good_path[512];
 snprintf(good_path, sizeof(good_path), "%s/good.bin", root);
 int fd = open(good_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
 assert(fd >= 0);
 assert(write(fd, "ok", 2) == 2);
 close(fd);

 int vfd = csg_open_trusted_file_at(root_fd, "/good.bin", my_uid);
 assert(vfd >= 0);
 close(vfd);

 /* Relative path rejected */
 assert(csg_open_trusted_file_at(root_fd, "good.bin", my_uid) < 0);

 /* Group-writable file rejected */
 assert(chmod(good_path, 0620) == 0);
 assert(csg_open_trusted_file_at(root_fd, "/good.bin", my_uid) < 0);
 assert(chmod(good_path, 0600) == 0);

 /* Hardlink (st_nlink > 1) rejected (VULN-LAUNCH-006) */
 char link_path[512];
 snprintf(link_path, sizeof(link_path), "%s/hardlink.bin", root);
 assert(link(good_path, link_path) == 0);
 assert(csg_open_trusted_file_at(root_fd, "/good.bin", my_uid) < 0);
 unlink(link_path);

 /* Symlink rejected */
 char sym_path[512];
 snprintf(sym_path, sizeof(sym_path), "%s/sym.bin", root);
 assert(symlink(good_path, sym_path) == 0);
 assert(csg_open_trusted_file_at(root_fd, "/sym.bin", my_uid) < 0);
 unlink(sym_path);

 /* Receipt exclusive creation (O_EXCL) */
 int rfd = csg_open_trusted_receipt_at(root_fd, "/receipt.jsonl", my_uid);
 assert(rfd >= 0);
 close(rfd);
 assert(csg_open_trusted_receipt_at(root_fd, "/receipt.jsonl", my_uid) < 0);

 char rpath[512];
 snprintf(rpath, sizeof(rpath), "%s/receipt.jsonl", root);
 unlink(rpath);
 unlink(good_path);
 close(root_fd);
 rmdir(root);
 g_tests_passed++;
}

static pthread_mutex_t g_gate_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_gate_cv  = PTHREAD_COND_INITIALIZER;
static bool            g_gate_Hold = false;
static unsigned        g_sync_calls = 0;

static int gated_fsync(int fd)
{
 pthread_mutex_lock(&g_gate_mtx);
 g_sync_calls++;
 pthread_cond_broadcast(&g_gate_cv);
 while (g_gate_Hold) {
  pthread_cond_wait(&g_gate_cv, &g_gate_mtx);
 }
 pthread_mutex_unlock(&g_gate_mtx);
 return fsync(fd);
}

static void *release_gate_after_30ms(void *arg)
{
 (void)arg;
 struct timespec ts = { .tv_sec = 0, .tv_nsec = 30000000L };
 nanosleep(&ts, NULL);
 pthread_mutex_lock(&g_gate_mtx);
 g_gate_Hold = false;
 pthread_cond_broadcast(&g_gate_cv);
 pthread_mutex_unlock(&g_gate_mtx);
 return NULL;
}

static void test_receipt_writer_full_queue_drain(void)
{
 /* Regression test for VULN-LAUNCH-004:
  * Fill all 64 queue slots while worker is mid-write on record #1, then release
  * worker after 30ms (within the 200ms close deadline). Verify csg_receipt_close
  * does NOT drop the sentinel or lose any of the 65 total records. */
 char tmpl[] = "/tmp/csg-rcpt-test-XXXXXX";
 int fd = mkstemp(tmpl);
 assert(fd >= 0);
 unlink(tmpl);

 pthread_mutex_lock(&g_gate_mtx);
 g_gate_Hold = true;
 g_sync_calls = 0;
 pthread_mutex_unlock(&g_gate_mtx);

 struct csg_receipt_writer *w = csg_receipt_create(fd, gated_fsync);
 assert(w != NULL);

 /* First record gets popped by worker, which then pauses inside gated_fsync */
 assert(csg_receipt_enqueue_raw(w, "evt", "\"n\":0"));
 pthread_mutex_lock(&g_gate_mtx);
 while (g_sync_calls == 0) {
  pthread_cond_wait(&g_gate_cv, &g_gate_mtx);
 }
 pthread_mutex_unlock(&g_gate_mtx);

 /* Now fill all 64 slots of the ring buffer */
 for (unsigned i = 1; i <= CSG_RECEIPT_QUEUE_CAP; i++) {
  char body[32];
  snprintf(body, sizeof(body), "\"n\":%u", i);
  assert(csg_receipt_enqueue_raw(w, "evt", body));
 }

 pthread_t releaser;
 assert(pthread_create(&releaser, NULL, release_gate_after_30ms, NULL) == 0);

 assert(csg_receipt_close(w, 1000));
 pthread_join(releaser, NULL);
 g_tests_passed++;
}

/* --- 3. Full Orchestration & Vulnerability Regression Scenarios --- */
struct mock_env {
 const char *scenario;
 char        root[512];
 int         root_fd;
 unsigned    status_calls;
 unsigned    cmd_count;
 char        cmds[16][128];
 unsigned    kill_count;
 int         kill_sigs[8];
 pid_t       kill_pgids[8];
 bool        stall_sync;
 bool        signal_in_disconnect;
};

static uid_t mock_get_euid(void *ctx)
{
 (void)ctx;
 return 0;
}

static int mock_get_release(void *ctx, char *buf, size_t cap)
{
 (void)ctx;
 snprintf(buf, cap, "test");
 return 0;
}

static int mock_set_no_new_privs(void *ctx)
{
 (void)ctx;
 return 0;
}

static int mock_run_cmd(void *ctx, const char *const *argv, char *out, size_t cap)
{
 struct mock_env *m = (struct mock_env *)ctx;
 if (m->cmd_count < 16) {
  snprintf(m->cmds[m->cmd_count], sizeof(m->cmds[0]), "%s:%s:%s",
           argv[0] ? argv[0] : "",
           argv[1] ? argv[1] : "",
           (argv[1] && strcmp(argv[1], "link") == 0 && argv[5]) ? argv[5] : "");
  m->cmd_count++;
 }
 if (argv[1] && strcmp(argv[1], "attach") == 0) {
  if (strcmp(m->scenario, "attach-failure") == 0)
   return -1;
  if (strcmp(m->scenario, "signal-after-attach") == 0)
   raise(SIGTERM);
  snprintf(out, cap,
           "{\"interface\":\"tap01\",\"ifindex\":5,\"netns_inode\":999,\"prog_id\":88}");
  return 0;
 }
 if (argv[1] && strcmp(argv[1], "status") == 0) {
  m->status_calls++;
  if ((strcmp(m->scenario, "runtime-loss") == 0 ||
       strcmp(m->scenario, "runtime-loss-blocked") == 0 ||
       strcmp(m->scenario, "signal-in-quarantine") == 0 ||
       strcmp(m->scenario, "wait-timeout-quarantine") == 0 ||
       strcmp(m->scenario, "quarantine-disconnect-fail") == 0) &&
      m->status_calls >= 3) {
   return -1;
  }
  if (strcmp(m->scenario, "prelaunch-loss") == 0 && m->status_calls >= 2)
   return -1;
  snprintf(out, cap,
           "{\"interface\":\"tap01\",\"ifindex\":5,\"netns_inode\":999,\"prog_id\":88}");
  return 0;
 }
 if (argv[1] && strcmp(argv[1], "-j") == 0) {
  if (m->signal_in_disconnect) {
   /* VULN-LAUNCH-001 regression: raise SIGTERM while inside disconnect() */
   raise(SIGTERM);
  }
  if (strcmp(m->scenario, "cleanup-disconnect-fail") == 0 ||
      strcmp(m->scenario, "quarantine-disconnect-fail") == 0) {
   snprintf(out, cap, "[{\"ifindex\":99,\"alias\":\"tap\\u0030\"}]");
   return 0;
  }
  snprintf(out, cap, "[{\"ifindex\":5,\"alias\":\"tap\\u0030\"}]");
  return 0;
 }
 if (out && cap > 0)
  out[0] = '\0';
 return 0;
}

static pid_t mock_spawn_vmm(void *ctx, char *const *argv, uid_t uid, gid_t gid)
{
 (void)ctx;
 assert(argv[0] != NULL && strcmp(argv[0], "/usr/bin/true") == 0);
 assert(uid == 1001 && gid == 1001);
 return 123456;
}

static int mock_poll_vmm(void *ctx, pid_t pid, int *exit_code_out)
{
 struct mock_env *m = (struct mock_env *)ctx;
 assert(pid == 123456);
 if (strcmp(m->scenario, "runtime-loss") == 0 ||
     strcmp(m->scenario, "runtime-loss-blocked") == 0 ||
     strcmp(m->scenario, "signal-in-quarantine") == 0 ||
     strcmp(m->scenario, "wait-timeout-quarantine") == 0 ||
     strcmp(m->scenario, "quarantine-disconnect-fail") == 0) {
  if (m->status_calls < 3)
   return 0; /* running */
 }
 *exit_code_out = 0;
 return 1; /* exited */
}

static int mock_kill_pg(void *ctx, pid_t pgid, int sig)
{
 struct mock_env *m = (struct mock_env *)ctx;
 if (m->kill_count < 8) {
  m->kill_pgids[m->kill_count] = pgid;
  m->kill_sigs[m->kill_count]  = sig;
  m->kill_count++;
 }
 return 0;
}

static int mock_wait_vmm(void *ctx, pid_t pid, unsigned timeout_ms, int *exit_code_out)
{
 struct mock_env *m = (struct mock_env *)ctx;
 (void)pid;
 (void)timeout_ms;
 if (strcmp(m->scenario, "wait-timeout-quarantine") == 0) {
  /* VULN-LAUNCH-003 regression: wait_vmm timeout must not skip receipt */
  errno = ETIMEDOUT;
  return -1;
 }
 if (exit_code_out)
  *exit_code_out = 0;
 return 0;
}

static bool g_stall_fsync_active = false;
static int mock_fsync(int fd)
{
 if (g_stall_fsync_active) {
  struct timespec ts = { .tv_sec = 0, .tv_nsec = 350000000L }; /* 350ms > 200ms */
  nanosleep(&ts, NULL);
 }
 return fsync(fd);
}

static void mock_sleep(void *ctx, double seconds)
{
 (void)ctx;
 (void)seconds;
}

static void verify_receipt_hash_chain(const char *receipt_text)
{
 char prev[65];
 memset(prev, '0', 64);
 prev[64] = '\0';
 uint64_t expected_seq = 1;
 const char *line = receipt_text;
 while (*line != '\0') {
  const char *nl = strchr(line, '\n');
  assert(nl != NULL);
  size_t line_len = (size_t)(nl - line);
  assert(line_len > 0 && line_len <= CSG_RECEIPT_MAX_LINE);

  char seq_pat[32];
  snprintf(seq_pat, sizeof(seq_pat), "{\"seq\":%llu,", (unsigned long long)expected_seq);
  assert(strncmp(line, seq_pat, strlen(seq_pat)) == 0);

  char prev_pat[96];
  snprintf(prev_pat, sizeof(prev_pat), "\"prev_sha256\":\"%s\",\"entry_sha256\":\"", prev);
  const char *p = strstr(line, prev_pat);
  assert(p != NULL && p < nl);

  const char *entry_tag = strstr(line, ",\"entry_sha256\":\"");
  assert(entry_tag != NULL && entry_tag < nl);
  size_t prefix_len = (size_t)(entry_tag - line);

  char computed[65];
  csg_sha256_hex(line, prefix_len, computed);
  const char *got_hash = entry_tag + strlen(",\"entry_sha256\":\"");
  assert(strncmp(got_hash, computed, 64) == 0);
  memcpy(prev, computed, 65);

  expected_seq++;
  line = nl + 1;
 }
 assert(expected_seq > 1);
}

static int run_scenario(const char *scenario, struct mock_env *m_out,
                        char *receipt_buf, size_t receipt_cap)
{
 if (receipt_buf && receipt_cap > 0)
  receipt_buf[0] = '\0';

 struct mock_env m;
 memset(&m, 0, sizeof(m));
 m.scenario = scenario;
 m.signal_in_disconnect = (strcmp(scenario, "signal-in-quarantine") == 0);
 g_stall_fsync_active = (strcmp(scenario, "runtime-loss-blocked") == 0);

 strcpy(m.root, "/tmp/csg-orch-XXXXXX");
 assert(mkdtemp(m.root) != NULL);
 assert(chmod(m.root, 0700) == 0);
 m.root_fd = open(m.root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
 assert(m.root_fd >= 0);

 char loader_real[560], obj_real[560], ev_real[560], rcpt_real[560];
 snprintf(loader_real, sizeof(loader_real), "%s/loader", m.root);
 snprintf(obj_real, sizeof(obj_real), "%s/guard.o", m.root);
 snprintf(ev_real, sizeof(ev_real), "%s/appraisal.json", m.root);
 snprintf(rcpt_real, sizeof(rcpt_real), "%s/receipt.jsonl", m.root);

 int fd = open(loader_real, O_WRONLY | O_CREAT | O_TRUNC, 0700);
 assert(fd >= 0);
 assert(write(fd, "loader", 6) == 6);
 close(fd);

 const char *obj_content = "fixture";
 fd = open(obj_real, O_WRONLY | O_CREAT | O_TRUNC, 0600);
 assert(fd >= 0);
 assert(write(fd, obj_content, strlen(obj_content)) == (ssize_t)strlen(obj_content));
 close(fd);

 char obj_sha[65];
 csg_sha256_hex(obj_content, strlen(obj_content), obj_sha);

 char ev_json[1024];
 snprintf(ev_json, sizeof(ev_json),
          "{\"schema_version\":\"csumguard-admission/v1\","
          "\"running_kernel\":\"test\","
          "\"guard_sha256\":\"%s\","
          "\"kernel_package\":\"test\","
          "\"fix_reference\":\"test\","
          "\"validation_receipt\":\"test\","
          "\"kernel_patch_verified\":%s,"
          "\"network_path_validated\":true,"
          "\"backend_metadata_validated\":true,"
          "\"compatibility_validated\":true,"
          "\"exclusive_tc_owner\":true}",
          obj_sha,
          strcmp(scenario, "invalid-evidence") == 0 ? "false" : "true");
 fd = open(ev_real, O_WRONLY | O_CREAT | O_TRUNC, 0600);
 assert(fd >= 0);
 assert(write(fd, ev_json, strlen(ev_json)) == (ssize_t)strlen(ev_json));
 close(fd);

 struct csg_launch_ops ops = {
  .ctx              = &m,
  .get_euid         = mock_get_euid,
  .trusted_uid      = geteuid(),
  .root_fd          = m.root_fd,
  .get_release      = mock_get_release,
  .set_no_new_privs = mock_set_no_new_privs,
  .run_cmd          = mock_run_cmd,
  .spawn_vmm        = mock_spawn_vmm,
  .poll_vmm         = mock_poll_vmm,
  .kill_pg          = mock_kill_pg,
  .wait_vmm         = mock_wait_vmm,
  .fsync_fn         = mock_fsync,
  .sleep_seconds    = mock_sleep
 };

 char *vmm_bin = (strcmp(scenario, "relative-vmm") == 0) ? "true" : "/usr/bin/true";
 char *argv[] = {
  "csumguard_launch",
  "--interface", "tap01",
  "--loader", "/loader",
  "--object", "/guard.o",
  "--evidence", "/appraisal.json",
  "--receipt", "/receipt.jsonl",
  "--uid", "1001",
  "--gid", "1001",
  "--", vmm_bin, NULL
 };
 int argc = 17;
 char err_msg[512] = "";
 int rc = csg_launch_run(argc, argv, &ops, err_msg, sizeof(err_msg));

 /* Unblock signals that csg_launch_run masked during teardown */
 sigset_t unblock;
 sigemptyset(&unblock);
 sigaddset(&unblock, SIGINT);
 sigaddset(&unblock, SIGTERM);
 sigaddset(&unblock, SIGHUP);
 pthread_sigmask(SIG_UNBLOCK, &unblock, NULL);

 if (g_stall_fsync_active) {
  /* Let detached stalled thread finish before unlinking temp dir */
  struct timespec ts = { .tv_sec = 0, .tv_nsec = 250000000L };
  nanosleep(&ts, NULL);
  g_stall_fsync_active = false;
 }

 int rfd = open(rcpt_real, O_RDONLY);
 if (rfd >= 0) {
  ssize_t n = read(rfd, receipt_buf, receipt_cap - 1);
  if (n > 0)
   receipt_buf[n] = '\0';
  close(rfd);
  unlink(rcpt_real);
 }
 unlink(loader_real);
 unlink(obj_real);
 unlink(ev_real);
 close(m.root_fd);
 rmdir(m.root);

 if (m_out)
  *m_out = m;
 return rc;
}

static bool has_down_call(const struct mock_env *m)
{
 for (unsigned i = 0; i < m->cmd_count; i++) {
  if (strstr(m->cmds[i], ":link:down") != NULL)
   return true;
 }
 return false;
}

static bool has_up_call(const struct mock_env *m)
{
 for (unsigned i = 0; i < m->cmd_count; i++) {
  if (strstr(m->cmds[i], ":link:up") != NULL)
   return true;
 }
 return false;
}

static void test_normal_exit_disconnects(void)
{
 struct mock_env m;
 char rcpt[8192];
 int rc = run_scenario("valid", &m, rcpt, sizeof(rcpt));
 assert(rc == 0);
 assert(has_down_call(&m));
 assert(strstr(rcpt, "\"event\":\"operator_evidence_accepted\"") != NULL);
 assert(strstr(rcpt, "\"event\":\"launched\"") != NULL);
 assert(strstr(rcpt, "\"event\":\"exited\"") != NULL);
 verify_receipt_hash_chain(rcpt);
 g_tests_passed++;
}

static void test_cleanup_disconnect_failure_returns_nonzero(void)
{
 /* Regression test for VULN-LAUNCH-002 */
 struct mock_env m;
 char rcpt[8192];
 int rc = run_scenario("cleanup-disconnect-fail", &m, rcpt, sizeof(rcpt));
 assert(rc != 0);
 assert(strstr(rcpt, "\"event\":\"cleanup_disconnect_failed\"") != NULL);
 verify_receipt_hash_chain(rcpt);
 g_tests_passed++;
}

static void test_invalid_evidence_never_touches_network(void)
{
 struct mock_env m;
 char rcpt[8192];
 int rc = run_scenario("invalid-evidence", &m, rcpt, sizeof(rcpt));
 assert(rc != 0);
 assert(m.cmd_count == 0);
 g_tests_passed++;
}

static void test_attach_failure_never_launches(void)
{
 struct mock_env m;
 char rcpt[8192];
 int rc = run_scenario("attach-failure", &m, rcpt, sizeof(rcpt));
 assert(rc != 0);
 assert(m.kill_count == 0);
 assert(strstr(rcpt, "\"event\":\"launched\"") == NULL);
 assert(strstr(rcpt, "\"event\":\"denied_or_quarantined\"") != NULL);
 assert(strstr(rcpt, "\"lifecycle\":\"quarantined\"") != NULL);
 verify_receipt_hash_chain(rcpt);
 g_tests_passed++;
}

static void test_loss_after_up_never_launches(void)
{
 struct mock_env m;
 char rcpt[8192];
 int rc = run_scenario("prelaunch-loss", &m, rcpt, sizeof(rcpt));
 assert(rc != 0);
 assert(has_down_call(&m));
 assert(strstr(rcpt, "\"event\":\"launched\"") == NULL);
 assert(strstr(rcpt, "\"event\":\"denied_or_quarantined\"") != NULL);
 assert(strstr(rcpt, "\"lifecycle\":\"quarantined\"") != NULL);
 assert(strstr(rcpt, "\"presence\":\"UNKNOWN\"") != NULL);
 verify_receipt_hash_chain(rcpt);
 g_tests_passed++;
}

static void test_blocked_receipt_does_not_stall_containment(void)
{
 struct mock_env m;
 char rcpt[8192];
 uint64_t t0 = csg_monotonic_ns();
 int rc = run_scenario("runtime-loss-blocked", &m, rcpt, sizeof(rcpt));
 uint64_t elapsed_ms = (csg_monotonic_ns() - t0) / 1000000ull;
 assert(rc != 0);
 assert(elapsed_ms < 1000ull);
 assert(m.kill_count == 2);
 assert(m.kill_sigs[0] == SIGSTOP);
 assert(m.kill_sigs[1] == SIGKILL);
 assert(has_down_call(&m));
 g_tests_passed++;
}

static void test_runtime_loss_pauses_and_disconnects(void)
{
 struct mock_env m;
 char rcpt[8192];
 int rc = run_scenario("runtime-loss", &m, rcpt, sizeof(rcpt));
 assert(rc != 0);
 assert(m.kill_count == 2);
 assert(m.kill_pgids[0] == 123456 && m.kill_sigs[0] == SIGSTOP);
 assert(m.kill_pgids[1] == 123456 && m.kill_sigs[1] == SIGKILL);
 assert(has_down_call(&m));
 assert(strstr(rcpt, "\"event\":\"denied_or_quarantined\"") != NULL);
 assert(strstr(rcpt, "\"lifecycle\":\"quarantined\"") != NULL);
 assert(strstr(rcpt, "\"evidence\":\"VERIFIED\"") != NULL);
 assert(strstr(rcpt, "\"event\":\"cleanup_disconnect_failed\"") == NULL);
 verify_receipt_hash_chain(rcpt);
 g_tests_passed++;
}

static void test_pgid_containment_on_wait_timeout(void)
{
 /* Regression test for VULN-LAUNCH-003 */
 struct mock_env m;
 char rcpt[8192];
 int rc = run_scenario("wait-timeout-quarantine", &m, rcpt, sizeof(rcpt));
 assert(rc != 0);
 assert(m.kill_count == 2);
 assert(m.kill_sigs[0] == SIGSTOP);
 assert(m.kill_sigs[1] == SIGKILL);
 assert(has_down_call(&m));
 assert(strstr(rcpt, "\"event\":\"denied_or_quarantined\"") != NULL);
 verify_receipt_hash_chain(rcpt);
 g_tests_passed++;
}

static void test_signal_during_quarantine_cannot_abort_disconnect(void)
{
 /* Regression test for VULN-LAUNCH-001 */
 struct mock_env m;
 char rcpt[8192];
 int rc = run_scenario("signal-in-quarantine", &m, rcpt, sizeof(rcpt));
 assert(rc != 0);
 assert(m.kill_count == 2);
 assert(m.kill_sigs[0] == SIGSTOP);
 assert(m.kill_sigs[1] == SIGKILL);
 assert(has_down_call(&m));
 assert(strstr(rcpt, "\"event\":\"denied_or_quarantined\"") != NULL);
 verify_receipt_hash_chain(rcpt);
 g_tests_passed++;
}

static void test_quarantine_disconnect_failure_recorded(void)
{
 struct mock_env m;
 char rcpt[8192];
 int rc = run_scenario("quarantine-disconnect-fail", &m, rcpt, sizeof(rcpt));
 assert(rc != 0);
 assert(m.kill_count == 2);
 assert(m.kill_sigs[0] == SIGSTOP);
 assert(m.kill_sigs[1] == SIGKILL);
 assert(strstr(rcpt, "\"event\":\"disconnect_failed\"") != NULL);
 assert(strstr(rcpt, "\"event\":\"denied_or_quarantined\"") != NULL);
 assert(strstr(rcpt, "\"event\":\"cleanup_disconnect_failed\"") == NULL);
 verify_receipt_hash_chain(rcpt);
 g_tests_passed++;
}

static void test_prelaunch_signal_aborts_before_up(void)
{
 struct mock_env m;
 char rcpt[8192];
 int rc = run_scenario("signal-after-attach", &m, rcpt, sizeof(rcpt));
 assert(rc != 0);
 assert(!has_up_call(&m));
 assert(has_down_call(&m));
 assert(strstr(rcpt, "\"event\":\"launched\"") == NULL);
 assert(strstr(rcpt, "\"event\":\"denied_or_quarantined\"") != NULL);
 assert(strstr(rcpt, "\"lifecycle\":\"quarantined\"") != NULL);
 verify_receipt_hash_chain(rcpt);
 g_tests_passed++;
}

static void test_relative_vmm_command_denied(void)
{
 struct mock_env m;
 char rcpt[8192];
 int rc = run_scenario("relative-vmm", &m, rcpt, sizeof(rcpt));
 assert(rc == 2);
 assert(m.cmd_count == 0);
 g_tests_passed++;
}

int main(void)
{
 test_sha256_fips_vectors();
 test_valid_evidence();
 test_every_missing_appraisal_denies();
 test_identity_mismatch_denies();
 test_evidence_references_required();
 test_no_launch_before_ready();
 test_ready_mismatch_denies();
 test_valid_lifecycle();
 test_each_identity_loss_quarantines();
 test_missing_observation_quarantines();
 test_invalid_identity_denies();
 test_trusted_filesystem_checks();
 test_receipt_writer_full_queue_drain();
 test_normal_exit_disconnects();
 test_cleanup_disconnect_failure_returns_nonzero();
 test_invalid_evidence_never_touches_network();
 test_attach_failure_never_launches();
 test_loss_after_up_never_launches();
 test_blocked_receipt_does_not_stall_containment();
 test_runtime_loss_pauses_and_disconnects();
 test_pgid_containment_on_wait_timeout();
 test_signal_during_quarantine_cannot_abort_disconnect();
 test_quarantine_disconnect_failure_recorded();
 test_prelaunch_signal_aborts_before_up();
 test_relative_vmm_command_denied();

 printf("PASS %u native C11 launch admission, vector-state, and containment orchestration checks\n",
        g_tests_passed);
 return 0;
}
