# csumguard

[![Status](https://img.shields.io/badge/Status-v0.2.0--candidate-d97706.svg)](VALIDATION.md)
[![Language](https://img.shields.io/badge/C-C11-00599C.svg)](Makefile)
[![Datapath](https://img.shields.io/badge/eBPF-TC%20clsact%20%2B%20CO--RE-2ea44f.svg)](csumguard_tc.bpf.c)
[![Sanitizers](https://img.shields.io/badge/ASan%20%2B%20UBSan-passing-2ea44f.svg)](evidence/sanitizer-execution.log)
[![License](https://img.shields.io/badge/License-GPL--2.0-blue.svg)](LICENSE)

Restricted TC ingress packet-admission guard, optional `skb_checksum_help` detector, verified loader, and supervised VMM launcher for interim containment of [CVE-2026-99999](docs/references.md). The entire stack is C11 and eBPF with zero interpreted runtime scripts.

> **Status: v0.2.0 candidate.** Offline policy, detector predicate, launcher, and sanitizer suites pass: `16,553` packet and detector checks, `25` launcher suites, and `6` raw frame self-tests. Live BPF verifier load, `veth`/TAP containment, and target-kernel verification remain **BLOCKED** until executed on a target Linux hypervisor. See [VALIDATION.md](VALIDATION.md).
>
> **Shared C11 headers.** Packet classification in [`policy.h`](policy.h), detector invariants in [`detect_policy.h`](detect_policy.h), and launch governance in [`launch_policy.h`](launch_policy.h) are deterministic, I/O-free headers compiled into both the production binaries and the native test binaries.
>
> **Scope.** This source package narrows guest-to-host network traffic on an untrusted VM interface and automates fail-closed quarantine when the TC guard disappears. It **does not fix the Linux kernel** and is **not a certified product**. See [promotion-gates.yaml](promotion-gates.yaml).

## What works

- **Restricted TC ingress admission.** [`policy.h`](policy.h) and [`csumguard_tc.bpf.c`](csumguard_tc.bpf.c) admit only untagged Ethernet IPv4 TCP/UDP with `IHL == 5` and validated 42-byte Ethernet/IPv4 ARP request or reply frames, permitting zero-padded 60-byte minimum Ethernet frames. The classifier drops IPv4 `MF`, nonzero fragment offsets, reserved fragment flags, IP options, GSO metadata where `gso_size > 0` or `gso_segs > 1`, inline or accelerated VLAN tags, truncated or over-MTU frames, bad IPv4 header checksums, zero TCP ports, and zero UDP destination ports. Every packet updates one of 26 per-CPU reason counters in `csg_stats`.
- **Optional `skb_checksum_help` detector.** [`detect_policy.h`](detect_policy.h) and [`csumguard_detect.bpf.c`](csumguard_detect.bpf.c) attach read-only to `fentry/skb_checksum_help` with CO-RE. The probe checks `ip_summed == CHECKSUM_PARTIAL` before reading the checksum union, guards `network_header + ihl` against 16-bit wrap-around, and increments 4 bounded per-CPU counters in `csg_detect` when `csum_start < network_header + ihl`. It never blocks traffic.
- **Verified TC loader.** [`loader.c`](loader.c) walks every path component from `/` using `openat` with `O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW`, requires `uid == 0` and `(mode & 022) == 0` at every directory hop, snapshots the regular BPF object with `st_nlink == 1`, checks its SHA-256 digest and post-read `fstat`/EOF stability, requires the target interface to be `DOWN`, creates a fresh `clsact` hook, and prints attachment identity and reason counters as JSON. It never removes an active guard if the interface concurrently transitions `UP`.
- **Supervised VMM launcher.** [`launch_policy.h`](launch_policy.h) and [`launch.c`](launch.c) validate operator admission evidence under schema `csumguard-admission/v1` against `uname().release` and the staged BPF object digest before attachment. The child VMM drops privileges to a non-root UID/GID via `setgroups(0, NULL)`, `setresgid`/`setresuid`, `prctl(PR_SET_NO_NEW_PRIVS, 1)`, closed extra file descriptors, and a scrubbed environment while the parent polls `csumguard_loader status` across a 6D state vector: `presence`, `valence`, `coherence`, `evidence`, `lifecycle`, and `epoch`.
- **Signal-masked containment and hash-chained receipts.** On attachment loss or identity drift, [`launch.c`](launch.c) blocks `SIGINT`, `SIGTERM`, and `SIGHUP`, pauses the VMM process group with `kill(-pid, SIGSTOP)`, sets the interface `DOWN`, and terminates the process group with `kill(-pid, SIGKILL)`. FIPS 180-4 SHA-256 hash-chained JSONL receipts (`seq`, `prev_sha256`, `entry_sha256`) flush through a 64-slot pthread ring buffer with a `200ms` close deadline so disk stalls cannot delay quarantine.

## Boundaries that still matter

- **Private skb metadata.** TC ingress cannot inspect or clear driver-private `CHECKSUM_PARTIAL` (`csum_start` and `csum_offset`) fields on small TCP/UDP frames that pass L2/L3/L4 header checks. Until the host kernel or trusted virtio/TAP backend validates those offsets, small valid-looking TCP/UDP packets can still carry malformed checksum metadata.
- **Protocol exclusions.** IPv6, ICMP, IP options, VLANs, IPv4 fragmentation, and GSO are denied. Dropping ICMP disables ping and Path MTU Discovery; guest MTUs and host routes must match `EGRESS_MTU`.
- **Tunneling and host datapath.** UDP payloads are opaque, and ARP validation checks frame structure rather than address ownership. Host-side UDP encapsulation or decapsulation, GRO, bridge/netfilter hooks, `XFRM`, `NFQUEUE`, multiqueue TAP, hotplug, and CNI plugins require target-specific validation.
- **Polling window and process scope.** `csumguard_launch` is a userspace polling supervisor, not an atomic in-kernel lifecycle lock. Drift can occur between status polls, and VMM helpers that escape the session process group require an external cgroup controller.

## Quick start

```bash
make EGRESS_MTU=1500 all
make test
```

Stage the built binaries and BPF object into a root-owned, non-writable directory such as `/opt/csumguard`, keep the target interface `DOWN`, and verify attachment directly:

```bash
/opt/csumguard/csumguard_loader attach tap0 /opt/csumguard/csumguard_tc.bpf.o <EXPECTED_SHA256>
/opt/csumguard/csumguard_loader status tap0 <IFINDEX> <NETNS_INODE> <PROG_ID>
```

Launch a VMM under `csumguard_launch` after completing target validation and recording operator appraisal in `/etc/csumguard/admission.json`:

```bash
/opt/csumguard/csumguard_launch \
  --interface tap0 \
  --loader /opt/csumguard/csumguard_loader \
  --object /opt/csumguard/csumguard_tc.bpf.o \
  --evidence /etc/csumguard/admission.json \
  --receipt /var/log/csumguard/tap0.jsonl \
  --uid 65534 \
  --gid 65534 \
  --interval 0.2 \
  -- /usr/bin/qemu-system-x86_64 -netdev tap,id=n0,ifname=tap0,script=no,downscript=no
```

## Verifying the bundle

Every tracked source file, document, and evidence log is listed in [`SHA256SUMS`](SHA256SUMS):

```bash
shasum -a 256 -c SHA256SUMS
```

Run the offline test suite and the AddressSanitizer + UndefinedBehaviorSanitizer checks:

```bash
make test
clang -std=c11 -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -Wall -Wextra -Werror \
  -DEGRESS_MTU=1500 -I. tests/test_policy.c -o /tmp/test_policy_asan && /tmp/test_policy_asan
clang -std=c11 -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -Wall -Wextra -Werror \
  -I. tests/test_launch.c -lpthread -o /tmp/test_launch_asan && /tmp/test_launch_asan
clang -std=c11 -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -Wall -Wextra -Werror \
  tests/send_frame.c -o /tmp/send_frame_asan && /tmp/send_frame_asan --self-test
```

## Build targets

```shell
make EGRESS_MTU=1500 all           build TC BPF object, loader, launcher, and frame sender on Linux
make test                          offline unit tests for policy, detector, launcher, and frame sender
make detector                      build optional fentry/skb_checksum_help CO-RE object on Linux with BTF
make clean                         remove build/ artifacts and temporary vmlinux headers
sudo bash testbed.sh               run disposable veth fixture on an isolated Linux lab host; exits 77 if skipped
```

`EGRESS_MTU` must be between `68` and `65535` and must not exceed the smallest post-encapsulation route MTU on the host. Changing `EGRESS_MTU` invalidates compiled BPF objects and admission digests.

## Repository layout

```shell
policy.h                  Pure C11 restricted L2/L3/L4 packet-admission classifier and reason codes
detect_policy.h           Pure C11 predicate for suspicious CHECKSUM_PARTIAL offsets
launch_policy.h           Pure C11 admission validator, 6D vector state, JSON parser, and FIPS 180-4 SHA-256
csumguard_tc.bpf.c        TC ingress clsact eBPF program and per-CPU reason counter map csg_stats
csumguard_detect.bpf.c    Optional fentry/skb_checksum_help CO-RE probe and counter map csg_detect
loader.c                  Verified libbpf/OpenSSL TC loader and status inspector csumguard_loader
launch.c                  Supervised VMM launcher, containment engine, and hash-chained receipt writer
tests/                    Offline C11 test suites test_policy.c, test_launch.c, and raw sender send_frame.c
testbed.sh                Privileged Linux lab veth harness
docs/                     Operational runbook, admission contract, briefing PDF, and reference register
evidence/                 Recorded build logs, MTU boundary logs, sanitizer logs, and verification.json
promotion-gates.yaml      Machine-readable gate statuses and required target-environment evidence
```

## Design notes

- **Zero runtime script dependencies.** The loader, launcher, raw frame sender, and unit test suites are compiled C11 binaries, and `testbed.sh` is pure Bash. No language interpreter is needed on the hypervisor.
- **Shared header-only kernels.** `policy.h`, `detect_policy.h`, and `launch_policy.h` make no OS or I/O calls. Offline tests execute the exact C functions compiled into the BPF programs and supervisor.
- **Descriptor-chained file verification.** Both `loader.c` and `launch.c` walk every directory from `/` using `openat` with `O_NOFOLLOW | O_CLOEXEC`, rejecting symlinks, non-root owners, group- or world-writable directories, hardlinks where `st_nlink != 1`, and concurrent file writes.
- **Fail-closed hook lifecycle.** If `loader.c` fails after attaching the TC filter and the interface has concurrently transitioned `UP`, cleanup keeps the attached guard in place rather than tearing down `clsact` on a live interface.

## Documentation

| Document | Purpose |
| --- | --- |
| [VALIDATION.md](VALIDATION.md) | Verification matrix, MTU boundary results, and blocked target gates |
| [GATES.md](GATES.md) | Security audit gate ledger (`G1`..`G8`) and remediated vulnerability catalog |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Operator deployment, verification, quarantine handling, and detector usage |
| [docs/ADMISSION.md](docs/ADMISSION.md) | Admission schema (`csumguard-admission/v1`), 6D vector state, and receipt format |
| [docs/references.md](docs/references.md) | Dated primary references for CVE-2026-99999 and Linux kernel fixes |
| [tests/README.md](tests/README.md) | Offline C11 test suites and raw frame sender usage |
| [evidence/verification.json](evidence/verification.json) | Machine-readable verification summary and promotion gates |

## License

GPL-2.0. See [LICENSE](LICENSE).
