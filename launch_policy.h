/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CSUMGUARD_LAUNCH_POLICY_H
#define CSUMGUARD_LAUNCH_POLICY_H

/* Pure, deterministic, zero-I/O semantic kernel for csumguard_launch:
 * - FIPS 180-4 SHA-256 digest computation
 * - Strict JSON parsers for operator admission appraisal, loader identity, and ip link
 * - Strict 4-tuple runtime attachment identity comparator (csg_same_identity)
 * - Typed 6D Vector State S(e,t) = <P, V, C, E, L, tau> transition contract
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

#define CSG_IFNAMSIZ 16
#define CSG_SHA256_HEX_LEN 64
#define CSG_MAX_STR_LEN 256
#define CSG_RECEIPT_MAX_LINE 16384
#define CSG_RECEIPT_QUEUE_CAP 64

enum csg_presence {
 CSG_PRESENCE_EMPTY    = 0,
 CSG_PRESENCE_PRESENT  = 1,
 CSG_PRESENCE_UNKNOWN  = 2,
 CSG_PRESENCE_REDACTED = 3
};

enum csg_valence {
 CSG_VALENCE_NEUTRAL  = 0,
 CSG_VALENCE_POSITIVE = 1,
 CSG_VALENCE_NEGATIVE = 2,
 CSG_VALENCE_ANTI     = 3
};

enum csg_coherence {
 CSG_COHERENCE_COHERENT   = 0,
 CSG_COHERENCE_PARTIAL    = 1,
 CSG_COHERENCE_DECOHERENT = 2
};

enum csg_evidence_status {
 CSG_EVIDENCE_UNVERIFIED = 0,
 CSG_EVIDENCE_VERIFIED   = 1,
 CSG_EVIDENCE_OVERFLOWED = 2,
 CSG_EVIDENCE_FAILED     = 3
};

enum csg_lifecycle_phase {
 CSG_LIFECYCLE_INIT        = 0,
 CSG_LIFECYCLE_ATTACHED    = 1,
 CSG_LIFECYCLE_READY       = 2,
 CSG_LIFECYCLE_RUNNING     = 3,
 CSG_LIFECYCLE_QUARANTINED = 4,
 CSG_LIFECYCLE_EXITED      = 5
};

enum csg_decision {
 CSG_DECISION_ADMIT      = 0,
 CSG_DECISION_DENY       = 1,
 CSG_DECISION_QUARANTINE = 2
};

struct csg_vector_state {
 enum csg_presence        presence;
 enum csg_valence         valence;
 enum csg_coherence       coherence;
 enum csg_evidence_status evidence;
 enum csg_lifecycle_phase lifecycle;
 uint64_t                 epoch;
};

struct csg_identity {
 char     interface[CSG_IFNAMSIZ];
 uint32_t ifindex;
 uint64_t netns_inode;
 uint32_t prog_id;
 bool     has_interface;
 bool     has_ifindex;
 bool     has_netns_inode;
 bool     has_prog_id;
};

struct csg_evidence {
 char schema_version[CSG_MAX_STR_LEN];
 char running_kernel[CSG_MAX_STR_LEN];
 char guard_sha256[CSG_SHA256_HEX_LEN + 1];
 char kernel_package[CSG_MAX_STR_LEN];
 char fix_reference[CSG_MAX_STR_LEN];
 char validation_receipt[CSG_MAX_STR_LEN];
 bool kernel_patch_verified;
 bool network_path_validated;
 bool backend_metadata_validated;
 bool compatibility_validated;
 bool exclusive_tc_owner;
 bool has_schema_version;
 bool has_running_kernel;
 bool has_guard_sha256;
 bool has_kernel_package;
 bool has_fix_reference;
 bool has_validation_receipt;
 bool has_kernel_patch_verified;
 bool has_network_path_validated;
 bool has_backend_metadata_validated;
 bool has_compatibility_validated;
 bool has_exclusive_tc_owner;
};

struct csg_lifecycle {
 struct csg_identity     expected;
 struct csg_vector_state state;
};

static inline const char *csg_presence_str(enum csg_presence p)
{
 switch (p) {
 case CSG_PRESENCE_EMPTY:    return "EMPTY";
 case CSG_PRESENCE_PRESENT:  return "PRESENT";
 case CSG_PRESENCE_UNKNOWN:  return "UNKNOWN";
 case CSG_PRESENCE_REDACTED: return "REDACTED";
 }
 return "UNKNOWN";
}

static inline const char *csg_valence_str(enum csg_valence v)
{
 switch (v) {
 case CSG_VALENCE_NEUTRAL:  return "NEUTRAL";
 case CSG_VALENCE_POSITIVE: return "POSITIVE";
 case CSG_VALENCE_NEGATIVE: return "NEGATIVE";
 case CSG_VALENCE_ANTI:     return "ANTI";
 }
 return "NEUTRAL";
}

static inline const char *csg_coherence_str(enum csg_coherence c)
{
 switch (c) {
 case CSG_COHERENCE_COHERENT:   return "COHERENT";
 case CSG_COHERENCE_PARTIAL:    return "PARTIAL";
 case CSG_COHERENCE_DECOHERENT: return "DECOHERENT";
 }
 return "DECOHERENT";
}

static inline const char *csg_evidence_status_str(enum csg_evidence_status e)
{
 switch (e) {
 case CSG_EVIDENCE_UNVERIFIED: return "UNVERIFIED";
 case CSG_EVIDENCE_VERIFIED:   return "VERIFIED";
 case CSG_EVIDENCE_OVERFLOWED: return "OVERFLOWED";
 case CSG_EVIDENCE_FAILED:     return "FAILED";
 }
 return "FAILED";
}

static inline const char *csg_lifecycle_str(enum csg_lifecycle_phase l)
{
 switch (l) {
 case CSG_LIFECYCLE_INIT:        return "init";
 case CSG_LIFECYCLE_ATTACHED:    return "attached";
 case CSG_LIFECYCLE_READY:       return "ready";
 case CSG_LIFECYCLE_RUNNING:     return "running";
 case CSG_LIFECYCLE_QUARANTINED: return "quarantined";
 case CSG_LIFECYCLE_EXITED:      return "exited";
 }
 return "quarantined";
}

/* --- FIPS 180-4 SHA-256 --- */
static inline uint32_t csg_rotr32(uint32_t x, unsigned n)
{
 return (x >> n) | (x << (32u - n));
}

static inline void csg_sha256_block(uint32_t h[8], const unsigned char blk[64])
{
 static const uint32_t k[64] = {
  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
  0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
  0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
  0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
  0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
  0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
  0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
  0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
  0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcU, 0x53380d13u,
  0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
  0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
  0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
  0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
  0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
  0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
  0x90befffaU, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
 };
 uint32_t w[64];
 for (unsigned i = 0; i < 16; i++) {
  w[i] = ((uint32_t)blk[i * 4 + 0] << 24) |
         ((uint32_t)blk[i * 4 + 1] << 16) |
         ((uint32_t)blk[i * 4 + 2] << 8)  |
         ((uint32_t)blk[i * 4 + 3]);
 }
 for (unsigned i = 16; i < 64; i++) {
  uint32_t s0 = csg_rotr32(w[i - 15], 7) ^ csg_rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
  uint32_t s1 = csg_rotr32(w[i - 2], 17) ^ csg_rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
  w[i] = w[i - 16] + s0 + w[i - 7] + s1;
 }
 uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
 uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
 for (unsigned i = 0; i < 64; i++) {
  uint32_t S1 = csg_rotr32(e, 6) ^ csg_rotr32(e, 11) ^ csg_rotr32(e, 25);
  uint32_t ch = (e & f) ^ ((~e) & g);
  uint32_t temp1 = hh + S1 + ch + k[i] + w[i];
  uint32_t S0 = csg_rotr32(a, 2) ^ csg_rotr32(a, 13) ^ csg_rotr32(a, 22);
  uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
  uint32_t temp2 = S0 + maj;
  hh = g; g = f; f = e; e = d + temp1;
  d = c; c = b; b = a; a = temp1 + temp2;
 }
 h[0] += a; h[1] += b; h[2] += c; h[3] += d;
 h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static inline void csg_sha256_hex(const void *data, size_t len, char out_hex[65])
{
 uint32_t h[8] = {
  0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
  0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
 };
 const unsigned char *p = (const unsigned char *)data;
 size_t off = 0;
 while (len - off >= 64) {
  csg_sha256_block(h, p + off);
  off += 64;
 }
 unsigned char tail[128];
 memset(tail, 0, sizeof(tail));
 size_t rem = len - off;
 if (rem > 0)
  memcpy(tail, p + off, rem);
 tail[rem] = 0x80u;
 size_t blocks = (rem >= 56) ? 2u : 1u;
 uint64_t bits = (uint64_t)len * 8u;
 for (unsigned i = 0; i < 8; i++)
  tail[blocks * 64u - 8u + i] = (unsigned char)(bits >> ((7u - i) * 8u));
 csg_sha256_block(h, tail);
 if (blocks == 2u)
  csg_sha256_block(h, tail + 64);
 static const char hex[] = "0123456789abcdef";
 for (unsigned i = 0; i < 8; i++) {
  for (unsigned b = 0; b < 4; b++) {
   unsigned char byte = (unsigned char)(h[i] >> ((3u - b) * 8u));
   out_hex[(i * 4u + b) * 2u + 0u] = hex[byte >> 4];
   out_hex[(i * 4u + b) * 2u + 1u] = hex[byte & 0x0fu];
  }
 }
 out_hex[64] = '\0';
}

/* --- String & Identity Validation --- */
static inline bool csg_valid_sha256_hex(const char *s)
{
 if (!s) return false;
 for (size_t i = 0; i < CSG_SHA256_HEX_LEN; i++) {
  char c = s[i];
  if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
   return false;
 }
 return s[CSG_SHA256_HEX_LEN] == '\0';
}

static inline bool csg_valid_ifname(const char *s)
{
 if (!s || s[0] == '\0') return false;
 size_t i = 0;
 for (; s[i] != '\0'; i++) {
  if (i >= CSG_IFNAMSIZ - 1) return false;
  char c = s[i];
  if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
   return false;
 }
 return i > 0 && i < CSG_IFNAMSIZ;
}

static inline bool csg_has_nonspace(const char *s)
{
 if (!s) return false;
 bool nonspace = false;
 for (size_t i = 0; s[i] != '\0'; i++) {
  unsigned char c = (unsigned char)s[i];
  if (c < 0x20u || c == 0x7fu) return false;
  if (c != ' ') nonspace = true;
 }
 return nonspace;
}

static inline bool csg_valid_identity(const struct csg_identity *id)
{
 if (!id) return false;
 if (!id->has_interface || !id->has_ifindex || !id->has_netns_inode || !id->has_prog_id)
  return false;
 if (!csg_valid_ifname(id->interface))
  return false;
 return id->ifindex > 0 && id->netns_inode > 0 && id->prog_id > 0;
}

static inline bool csg_same_identity(const struct csg_identity *want,
                                     const struct csg_identity *got)
{
 if (!csg_valid_identity(want) || !csg_valid_identity(got))
  return false;
 return strcmp(want->interface, got->interface) == 0 &&
        want->ifindex == got->ifindex &&
        want->netns_inode == got->netns_inode &&
        want->prog_id == got->prog_id;
}

static inline int csg_validate_evidence(const struct csg_evidence *ev,
                                        const char *release,
                                        const char *digest)
{
 if (!ev || !release || !*release || !csg_valid_sha256_hex(digest))
  return -1;
 if (!ev->has_schema_version || strcmp(ev->schema_version, "csumguard-admission/v1") != 0)
  return -2;
 if (!ev->has_running_kernel || strcmp(ev->running_kernel, release) != 0)
  return -3;
 if (!ev->has_guard_sha256 || !csg_valid_sha256_hex(ev->guard_sha256) ||
     strcmp(ev->guard_sha256, digest) != 0)
  return -4;
 if (!ev->has_kernel_patch_verified || !ev->kernel_patch_verified ||
     !ev->has_network_path_validated || !ev->network_path_validated ||
     !ev->has_backend_metadata_validated || !ev->backend_metadata_validated ||
     !ev->has_compatibility_validated || !ev->compatibility_validated ||
     !ev->has_exclusive_tc_owner || !ev->exclusive_tc_owner)
  return -5;
 if (!ev->has_kernel_package || !csg_has_nonspace(ev->kernel_package) ||
     !ev->has_fix_reference || !csg_has_nonspace(ev->fix_reference) ||
     !ev->has_validation_receipt || !csg_has_nonspace(ev->validation_receipt))
  return -6;
 return 0;
}

/* --- Vector State & Lifecycle Transition Contract --- */
static inline void csg_lifecycle_fault(struct csg_lifecycle *lc,
                                       enum csg_presence p,
                                       enum csg_valence v,
                                       enum csg_coherence c)
{
 if (!lc) return;
 lc->state.epoch++;
 lc->state.presence  = p;
 lc->state.valence   = v;
 lc->state.coherence = c;
 lc->state.lifecycle = CSG_LIFECYCLE_QUARANTINED;
}

static inline int csg_lifecycle_init(struct csg_lifecycle *lc,
                                     const struct csg_identity *expected)
{
 if (!lc || !csg_valid_identity(expected))
  return -1;
 lc->expected = *expected;
 lc->state.presence  = CSG_PRESENCE_PRESENT;
 lc->state.valence   = CSG_VALENCE_POSITIVE;
 lc->state.coherence = CSG_COHERENCE_COHERENT;
 lc->state.evidence  = CSG_EVIDENCE_VERIFIED;
 lc->state.lifecycle = CSG_LIFECYCLE_ATTACHED;
 lc->state.epoch     = 1;
 return 0;
}

static inline enum csg_decision csg_lifecycle_ready(struct csg_lifecycle *lc,
                                                    const struct csg_identity *observed)
{
 if (!lc || (lc->state.lifecycle != CSG_LIFECYCLE_ATTACHED &&
             lc->state.lifecycle != CSG_LIFECYCLE_READY))
  return CSG_DECISION_DENY;
 lc->state.epoch++;
 if (!observed) {
  lc->state.presence  = CSG_PRESENCE_UNKNOWN;
  lc->state.valence   = CSG_VALENCE_NEUTRAL;
  lc->state.coherence = CSG_COHERENCE_DECOHERENT;
  lc->state.lifecycle = CSG_LIFECYCLE_QUARANTINED;
  return CSG_DECISION_DENY;
 }
 if (!csg_same_identity(&lc->expected, observed)) {
  lc->state.presence  = CSG_PRESENCE_PRESENT;
  lc->state.valence   = CSG_VALENCE_ANTI;
  lc->state.coherence = CSG_COHERENCE_DECOHERENT;
  lc->state.lifecycle = CSG_LIFECYCLE_QUARANTINED;
  return CSG_DECISION_DENY;
 }
 lc->state.presence  = CSG_PRESENCE_PRESENT;
 lc->state.valence   = CSG_VALENCE_POSITIVE;
 lc->state.coherence = CSG_COHERENCE_COHERENT;
 lc->state.lifecycle = CSG_LIFECYCLE_READY;
 return CSG_DECISION_ADMIT;
}

static inline enum csg_decision csg_lifecycle_started(struct csg_lifecycle *lc)
{
 if (!lc || lc->state.lifecycle != CSG_LIFECYCLE_READY)
  return CSG_DECISION_DENY;
 lc->state.epoch++;
 lc->state.lifecycle = CSG_LIFECYCLE_RUNNING;
 return CSG_DECISION_ADMIT;
}

static inline enum csg_decision csg_lifecycle_observe(struct csg_lifecycle *lc,
                                                      const struct csg_identity *observed)
{
 if (!lc || lc->state.lifecycle != CSG_LIFECYCLE_RUNNING)
  return CSG_DECISION_DENY;
 lc->state.epoch++;
 if (!observed) {
  lc->state.presence  = CSG_PRESENCE_UNKNOWN;
  lc->state.valence   = CSG_VALENCE_NEUTRAL;
  lc->state.coherence = CSG_COHERENCE_DECOHERENT;
  lc->state.lifecycle = CSG_LIFECYCLE_QUARANTINED;
  return CSG_DECISION_QUARANTINE;
 }
 if (!csg_same_identity(&lc->expected, observed)) {
  lc->state.presence  = CSG_PRESENCE_PRESENT;
  lc->state.valence   = CSG_VALENCE_ANTI;
  lc->state.coherence = CSG_COHERENCE_DECOHERENT;
  lc->state.lifecycle = CSG_LIFECYCLE_QUARANTINED;
  return CSG_DECISION_QUARANTINE;
 }
 lc->state.presence  = CSG_PRESENCE_PRESENT;
 lc->state.valence   = CSG_VALENCE_POSITIVE;
 lc->state.coherence = CSG_COHERENCE_COHERENT;
 return CSG_DECISION_ADMIT;
}

/* --- Strict Minimal JSON Lexer/Parsers --- */
struct csg_json_cursor {
 const char *src;
 size_t      len;
 size_t      pos;
};

static inline void csg_json_skip_ws(struct csg_json_cursor *c)
{
 while (c->pos < c->len) {
  char ch = c->src[c->pos];
  if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
   c->pos++;
  else
   break;
 }
}

static inline int csg_json_parse_str(struct csg_json_cursor *c, char *out, size_t cap)
{
 csg_json_skip_ws(c);
 if (c->pos >= c->len || c->src[c->pos] != '"')
  return -1;
 c->pos++;
 size_t w = 0;
 while (c->pos < c->len) {
  char ch = c->src[c->pos++];
  if (ch == '"') {
   if (out && cap > 0) out[w] = '\0';
   return 0;
  }
  if ((unsigned char)ch < 0x20u)
   return -1;
  if (ch == '\\') {
   if (c->pos >= c->len) return -1;
   char esc = c->src[c->pos++];
   switch (esc) {
   case '"': case '\\': case '/': ch = esc; break;
   case 'b': ch = '\b'; break;
   case 'f': ch = '\f'; break;
   case 'n': ch = '\n'; break;
   case 'r': ch = '\r'; break;
   case 't': ch = '\t'; break;
   case 'u': {
    if (c->len - c->pos < 4) return -1;
    unsigned code = 0;
    for (unsigned k = 0; k < 4; k++) {
     char hc = c->src[c->pos++];
     code <<= 4;
     if (hc >= '0' && hc <= '9') code |= (unsigned)(hc - '0');
     else if (hc >= 'a' && hc <= 'f') code |= (unsigned)(hc - 'a' + 10);
     else if (hc >= 'A' && hc <= 'F') code |= (unsigned)(hc - 'A' + 10);
     else return -1;
    }
    if (!out) continue;
    if (code < 0x20u || code >= 0x7fu) return -1;
    ch = (char)code;
    break;
   }
   default: return -1;
   }
  }
  if (out) {
   if (w + 1 >= cap) return -1;
   out[w++] = ch;
  }
 }
 return -1;
}

static inline int csg_json_parse_bool(struct csg_json_cursor *c, bool *out)
{
 csg_json_skip_ws(c);
 if (c->len - c->pos >= 4 && memcmp(c->src + c->pos, "true", 4) == 0) {
  c->pos += 4;
  *out = true;
  return 0;
 }
 if (c->len - c->pos >= 5 && memcmp(c->src + c->pos, "false", 5) == 0) {
  c->pos += 5;
  *out = false;
  return 0;
 }
 return -1;
}

static inline int csg_json_parse_u64(struct csg_json_cursor *c, uint64_t *out)
{
 csg_json_skip_ws(c);
 if (c->pos >= c->len) return -1;
 char first = c->src[c->pos];
 if (first < '1' || first > '9')
  return -1;
 uint64_t val = 0;
 while (c->pos < c->len) {
  char ch = c->src[c->pos];
  if (ch >= '0' && ch <= '9') {
   uint64_t digit = (uint64_t)(ch - '0');
   if (val > (UINT64_MAX - digit) / 10u)
    return -1;
   val = val * 10u + digit;
   c->pos++;
  } else {
   break;
  }
 }
 /* Reject trailing decimal point or exponent */
 if (c->pos < c->len && (c->src[c->pos] == '.' || c->src[c->pos] == 'e' || c->src[c->pos] == 'E'))
  return -1;
 *out = val;
 return 0;
}

static inline int csg_json_skip_value(struct csg_json_cursor *c, unsigned depth)
{
 if (depth > 8) return -1;
 csg_json_skip_ws(c);
 if (c->pos >= c->len) return -1;
 char ch = c->src[c->pos];
 if (ch == '"')
  return csg_json_parse_str(c, NULL, 0);
 if (ch == '{') {
  c->pos++;
  csg_json_skip_ws(c);
  if (c->pos < c->len && c->src[c->pos] == '}') {
   c->pos++;
   return 0;
  }
  for (;;) {
   if (csg_json_parse_str(c, NULL, 0) != 0) return -1;
   csg_json_skip_ws(c);
   if (c->pos >= c->len || c->src[c->pos] != ':') return -1;
   c->pos++;
   if (csg_json_skip_value(c, depth + 1) != 0) return -1;
   csg_json_skip_ws(c);
   if (c->pos < c->len && c->src[c->pos] == ',') {
    c->pos++;
    continue;
   }
   if (c->pos < c->len && c->src[c->pos] == '}') {
    c->pos++;
    return 0;
   }
   return -1;
  }
 }
 if (ch == '[') {
  c->pos++;
  csg_json_skip_ws(c);
  if (c->pos < c->len && c->src[c->pos] == ']') {
   c->pos++;
   return 0;
  }
  for (;;) {
   if (csg_json_skip_value(c, depth + 1) != 0) return -1;
   csg_json_skip_ws(c);
   if (c->pos < c->len && c->src[c->pos] == ',') {
    c->pos++;
    continue;
   }
   if (c->pos < c->len && c->src[c->pos] == ']') {
    c->pos++;
    return 0;
   }
   return -1;
  }
 }
 if (c->len - c->pos >= 4 && memcmp(c->src + c->pos, "true", 4) == 0) {
  c->pos += 4; return 0;
 }
 if (c->len - c->pos >= 5 && memcmp(c->src + c->pos, "false", 5) == 0) {
  c->pos += 5; return 0;
 }
 if (c->len - c->pos >= 4 && memcmp(c->src + c->pos, "null", 4) == 0) {
  c->pos += 4; return 0;
 }
 if (ch == '-' || (ch >= '0' && ch <= '9')) {
  if (ch == '-') c->pos++;
  if (c->pos >= c->len || c->src[c->pos] < '0' || c->src[c->pos] > '9')
   return -1;
  while (c->pos < c->len && ((c->src[c->pos] >= '0' && c->src[c->pos] <= '9') ||
                             c->src[c->pos] == '.' || c->src[c->pos] == 'e' ||
                             c->src[c->pos] == 'E' || c->src[c->pos] == '+' ||
                             c->src[c->pos] == '-'))
   c->pos++;
  return 0;
 }
 return -1;
}

static inline int csg_parse_evidence_json(const char *json, size_t len, struct csg_evidence *out)
{
 if (!json || !out) return -1;
 memset(out, 0, sizeof(*out));
 struct csg_json_cursor c = { .src = json, .len = len, .pos = 0 };
 csg_json_skip_ws(&c);
 if (c.pos >= c.len || c.src[c.pos] != '{') return -1;
 c.pos++;
 csg_json_skip_ws(&c);
 if (c.pos < c.len && c.src[c.pos] == '}') {
  c.pos++;
  csg_json_skip_ws(&c);
  return c.pos == c.len ? 0 : -1;
 }
 for (;;) {
  char key[64];
  if (csg_json_parse_str(&c, key, sizeof(key)) != 0) return -1;
  csg_json_skip_ws(&c);
  if (c.pos >= c.len || c.src[c.pos] != ':') return -1;
  c.pos++;
  if (strcmp(key, "schema_version") == 0) {
   if (out->has_schema_version ||
       csg_json_parse_str(&c, out->schema_version, sizeof(out->schema_version)) != 0)
    return -1;
   out->has_schema_version = true;
  } else if (strcmp(key, "running_kernel") == 0) {
   if (out->has_running_kernel ||
       csg_json_parse_str(&c, out->running_kernel, sizeof(out->running_kernel)) != 0)
    return -1;
   out->has_running_kernel = true;
  } else if (strcmp(key, "guard_sha256") == 0) {
   if (out->has_guard_sha256 ||
       csg_json_parse_str(&c, out->guard_sha256, sizeof(out->guard_sha256)) != 0)
    return -1;
   out->has_guard_sha256 = true;
  } else if (strcmp(key, "kernel_package") == 0) {
   if (out->has_kernel_package ||
       csg_json_parse_str(&c, out->kernel_package, sizeof(out->kernel_package)) != 0)
    return -1;
   out->has_kernel_package = true;
  } else if (strcmp(key, "fix_reference") == 0) {
   if (out->has_fix_reference ||
       csg_json_parse_str(&c, out->fix_reference, sizeof(out->fix_reference)) != 0)
    return -1;
   out->has_fix_reference = true;
  } else if (strcmp(key, "validation_receipt") == 0) {
   if (out->has_validation_receipt ||
       csg_json_parse_str(&c, out->validation_receipt, sizeof(out->validation_receipt)) != 0)
    return -1;
   out->has_validation_receipt = true;
  } else if (strcmp(key, "kernel_patch_verified") == 0) {
   if (out->has_kernel_patch_verified ||
       csg_json_parse_bool(&c, &out->kernel_patch_verified) != 0)
    return -1;
   out->has_kernel_patch_verified = true;
  } else if (strcmp(key, "network_path_validated") == 0) {
   if (out->has_network_path_validated ||
       csg_json_parse_bool(&c, &out->network_path_validated) != 0)
    return -1;
   out->has_network_path_validated = true;
  } else if (strcmp(key, "backend_metadata_validated") == 0) {
   if (out->has_backend_metadata_validated ||
       csg_json_parse_bool(&c, &out->backend_metadata_validated) != 0)
    return -1;
   out->has_backend_metadata_validated = true;
  } else if (strcmp(key, "compatibility_validated") == 0) {
   if (out->has_compatibility_validated ||
       csg_json_parse_bool(&c, &out->compatibility_validated) != 0)
    return -1;
   out->has_compatibility_validated = true;
  } else if (strcmp(key, "exclusive_tc_owner") == 0) {
   if (out->has_exclusive_tc_owner ||
       csg_json_parse_bool(&c, &out->exclusive_tc_owner) != 0)
    return -1;
   out->has_exclusive_tc_owner = true;
  } else {
   if (csg_json_skip_value(&c, 0) != 0) return -1;
  }
  csg_json_skip_ws(&c);
  if (c.pos < c.len && c.src[c.pos] == ',') {
   c.pos++;
   continue;
  }
  if (c.pos < c.len && c.src[c.pos] == '}') {
   c.pos++;
   break;
  }
  return -1;
 }
 csg_json_skip_ws(&c);
 return c.pos == c.len ? 0 : -1;
}

static inline int csg_parse_identity_json(const char *json, size_t len, struct csg_identity *out)
{
 if (!json || !out) return -1;
 memset(out, 0, sizeof(*out));
 struct csg_json_cursor c = { .src = json, .len = len, .pos = 0 };
 csg_json_skip_ws(&c);
 if (c.pos >= c.len || c.src[c.pos] != '{') return -1;
 c.pos++;
 csg_json_skip_ws(&c);
 if (c.pos < c.len && c.src[c.pos] == '}')
  return -1;
 for (;;) {
  char key[64];
  if (csg_json_parse_str(&c, key, sizeof(key)) != 0) return -1;
  csg_json_skip_ws(&c);
  if (c.pos >= c.len || c.src[c.pos] != ':') return -1;
  c.pos++;
  if (strcmp(key, "interface") == 0) {
   if (out->has_interface ||
       csg_json_parse_str(&c, out->interface, sizeof(out->interface)) != 0)
    return -1;
   out->has_interface = true;
  } else if (strcmp(key, "ifindex") == 0) {
   uint64_t v = 0;
   if (out->has_ifindex || csg_json_parse_u64(&c, &v) != 0 || v == 0 || v > UINT32_MAX)
    return -1;
   out->ifindex = (uint32_t)v;
   out->has_ifindex = true;
  } else if (strcmp(key, "netns_inode") == 0) {
   uint64_t v = 0;
   if (out->has_netns_inode || csg_json_parse_u64(&c, &v) != 0 || v == 0)
    return -1;
   out->netns_inode = v;
   out->has_netns_inode = true;
  } else if (strcmp(key, "prog_id") == 0) {
   uint64_t v = 0;
   if (out->has_prog_id || csg_json_parse_u64(&c, &v) != 0 || v == 0 || v > UINT32_MAX)
    return -1;
   out->prog_id = (uint32_t)v;
   out->has_prog_id = true;
  } else {
   if (csg_json_skip_value(&c, 0) != 0) return -1;
  }
  csg_json_skip_ws(&c);
  if (c.pos < c.len && c.src[c.pos] == ',') {
   c.pos++;
   continue;
  }
  if (c.pos < c.len && c.src[c.pos] == '}') {
   c.pos++;
   break;
  }
  return -1;
 }
 csg_json_skip_ws(&c);
 if (c.pos != c.len || !csg_valid_identity(out))
  return -1;
 return 0;
}

static inline int csg_parse_ip_link_ifindex(const char *json, size_t len, uint32_t *ifindex_out)
{
 if (!json || !ifindex_out) return -1;
 *ifindex_out = 0;
 struct csg_json_cursor c = { .src = json, .len = len, .pos = 0 };
 csg_json_skip_ws(&c);
 if (c.pos >= c.len || c.src[c.pos] != '[') return -1;
 c.pos++;
 csg_json_skip_ws(&c);
 if (c.pos >= c.len || c.src[c.pos] != '{') return -1;
 c.pos++;
 bool found = false;
 for (;;) {
  char key[64];
  if (csg_json_parse_str(&c, key, sizeof(key)) != 0) return -1;
  csg_json_skip_ws(&c);
  if (c.pos >= c.len || c.src[c.pos] != ':') return -1;
  c.pos++;
  if (strcmp(key, "ifindex") == 0) {
   uint64_t v = 0;
   if (found || csg_json_parse_u64(&c, &v) != 0 || v == 0 || v > UINT32_MAX)
    return -1;
   *ifindex_out = (uint32_t)v;
   found = true;
  } else {
   if (csg_json_skip_value(&c, 0) != 0) return -1;
  }
  csg_json_skip_ws(&c);
  if (c.pos < c.len && c.src[c.pos] == ',') {
   c.pos++;
   continue;
  }
  if (c.pos < c.len && c.src[c.pos] == '}') {
   c.pos++;
   break;
  }
  return -1;
 }
 csg_json_skip_ws(&c);
 /* Must be a single-element array: reject commas / extra link objects. */
 if (c.pos >= c.len || c.src[c.pos] != ']') return -1;
 c.pos++;
 csg_json_skip_ws(&c);
 if (c.pos != c.len || !found) return -1;
 return 0;
}

#endif /* CSUMGUARD_LAUNCH_POLICY_H */
