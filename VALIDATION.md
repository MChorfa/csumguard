# Validation receipt — v0.2.0 candidate

**Fix-workflow outcome: blocked. Implementation: candidate completed. CVE closed: no.**

The packet boundary is the restricted TC admission function shared between the
BPF adapter and native fixtures. The invariant tested here is that fragmented,
offloaded, unsupported or malformed packets do not pass this parser, while
in-profile positive controls do. It does not establish rejection of private
checksum metadata or closure of the kernel vulnerability.

## Ordered verification

| Gate | Command / setup | Result |
|---|---|---|
| Native build and regressions | `make test` | PASS: 16,553 policy/predicate checks, 25 C11 launch checks, 6 frame checks |
| Script syntax | `bash -n testbed.sh` | PASS |
| Memory / UB checks | ASan+UBSan build and execution (`test_policy`, `test_launch`, `send_frame`) | PASS |
| Config boundary | Rebuild native suite with MTUs 68, 1280, 9000, 65535 | PASS; configuration changes trigger rebuild |
| BPF compile | `make build/csumguard_tc.bpf.o` | BLOCKED: Linux BPF UAPI headers / target environment missing |
| Loader compile | `make build/csumguard_loader` | BLOCKED: libbpf headers missing |
| Optional detector compile | `make detector` | BLOCKED: bpftool / `/sys/kernel/btf/vmlinux` missing |
| Live veth | `bash testbed.sh` | SKIPPED, exit 77: required Linux capabilities unavailable |
| Real VMM/TAP and CVE trigger | Target fixture | NOT RUN: no target host/VMM/backend supplied |

The original candidate validation host kernel was 6.18.44, and the C11
refinement and sanitizer verification suite was executed natively under C11
with AddressSanitizer and UndefinedBehaviorSanitizer across `test_policy`,
`test_launch` and `send_frame`. This is local verification metadata, not
evidence about production hosts or whether a target kernel carries a backport.

## Original behavior and legitimate controls

A native adapter executes the original TC function body with helper shims. Five
assertions show original acceptance across four classes: small first/later IPv4
fragments, GSO, IPv6 pass-through and inconsistent IP lengths. The new shared
parser rejects those fixtures. That is a focused substitute for parser behavior,
not reproduction of CVE-2026-99999. Neither original bundled object nor executable
was run.

Positive controls retain in-profile TCP/UDP and ARP, DF, valid TCP options (with
tail-byte readability verification) and ordinary Ethernet padding. Truncated
prefixes, upper-bit `skb->protocol` poisoning, detector 16-bit `nh + ihl`
overflows and every MF/fragment-offset value are checked. Native boundary-MTU
fixtures adapt to the configured policy, including the IPv4 maximum where a
larger valid datagram cannot exist.

Native C11 launch tests (`tests/test_launch.c`) cover FIPS 180-4 SHA-256 vectors,
missing/false appraisals, mismatched kernel/object identity, stale or empty
interface/netns/program identity, 6D vector-state transitions (`UNKNOWN` vs
`ANTI`/`DECOHERENT`), descriptor-chained filesystem checks (`st_nlink == 1`,
`O_NOFOLLOW`, `O_EXCL`), full-queue receipt drain, normal cleanup, nonzero exit
on cleanup disconnect failure, signal-masked quarantine and PGID containment
using injected OS boundaries. A stalled receipt `fsync` is simulated while
attachment identity disappears; pause/disconnect calls occur without waiting for
that writer. These are not live privilege, kernel netns or supervisor-crash
tests.

## Candidate review corrections

The multi-domain security review addressed the following issues in C11:

- Receipt `fsync` on the supervision thread could stall monitoring, and a full
  64-slot queue could drop the close sentinel. A bounded asynchronous `pthread`
  writer now owns I/O, waits on `not_full` up to the close deadline before
  signaling drain, and emits SHA-256 hash-chained JSONL (`seq`, `prev_sha256`,
  `entry_sha256`).
- Signal re-entrancy during quarantine, conditional `SIGKILL` on session-leader
  status, and ignored cleanup disconnect errors were fixed in `launch.c`.
- `loader.c` now walks ancestor directories from `/` with `openat(..., O_NOFOLLOW)`,
  enforces `st_nlink == 1` and EOF/`fstat` stability, and never destroys a TC
  hook if the interface concurrently transitioned `UP`.
- `policy.h` checks upper bits of 32-bit `skb->protocol` on little-endian and
  probes the final byte of declared TCP options; `detect_policy.h` and
  `csumguard_detect.bpf.c` guard against `0xffff` unset `network_header` and
  16-bit `nh + ihl` wrap-around.

## Change inventory

`policy.h`, `detect_policy.h`, both BPF adapters, `loader.c`, `launch_policy.h`,
`launch.c`, `Makefile`, disposable `testbed.sh`, native C11 fixtures
(`tests/test_policy.c`, `tests/test_launch.c`, `tests/send_frame.c`),
documentation, promotion gates and evidence records. Original binaries are
omitted from this package.

The per-command logs and machine-readable [verification record](evidence/verification.json)
are authoritative for what ran. Required target checks are listed in
[promotion-gates.yaml](promotion-gates.yaml) and [the runbook](docs/RUNBOOK.md).
No deployment, signature, benchmark or production containment is claimed.
