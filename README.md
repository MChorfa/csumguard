# csumguard

[![CI](https://github.com/MChorfa/csumguard/actions/workflows/ci.yml/badge.svg)](https://github.com/MChorfa/csumguard/actions/workflows/ci.yml)
[![Status](https://img.shields.io/badge/Status-v0.2.0--candidate-d97706.svg)](VALIDATION.md)
[![Language](https://img.shields.io/badge/Language-C11%20%2B%20eBPF-00599C.svg)](Makefile)
[![Sanitizers](https://img.shields.io/badge/ASan%20%2B%20UBSan-passing-2ea44f.svg)](evidence/sanitizer-execution.log)
[![License](https://img.shields.io/badge/License-GPL--2.0-blue.svg)](LICENSE)

An interim packet-admission guard and supervised launcher for [CVE-2026-99999](docs/references.md).

It drops dangerous guest traffic on a VM's TAP interface before the host kernel can reach `skb_checksum_help`. Written in pure C11 and eBPF with zero interpreted scripts.

> **Status: v0.2.0 candidate.** All offline policy, detector, launcher, and sanitizer suites pass. Live hypervisor verification remains blocked until run on an isolated Linux host. See [VALIDATION.md](VALIDATION.md).
>
> **Scope.** This is a traffic filter that reduces attack surface. It is **not a kernel patch** and **does not certify safety**. Upstream kernel fixes are in [docs/references.md](docs/references.md).

---

## Architecture

```mermaid
flowchart LR
    subgraph Guest["Untrusted Guest VM"]
        VMM["VMM Process<br/>(QEMU / Cloud-Hypervisor)"]
    end

    subgraph Interface["Host TAP Device (tap0)"]
        TAP["tap0 (clsact)"]
        TC["csumguard_in<br/>(eBPF TC Ingress)"]
    end

    subgraph Host["Host Linux Kernel"]
        STACK["Host Network Stack"]
        SINK["skb_checksum_help<br/>(Vulnerable Sink)"]
    end

    subgraph Supervisor["csumguard_launch (C11 Supervisor)"]
        MON["Identity Poller<br/>(6D Vector State)"]
        QUAR["Quarantine Engine<br/>(SIGSTOP -> DOWN -> SIGKILL)"]
        RING["Hash-Chained Receipt Ring<br/>(64-slot, pthread)"]
    end

    VMM -->|TX Frames| TAP
    TAP --> TC
    TC -->|Admitted TCP/UDP/ARP| STACK
    TC -.->|DROPPED: Frag / GSO / VLAN / Opt| DROP["Dropped + Counter"]
    STACK -.-> SINK
    MON -->|Polls Status| TAP
    MON -->|Attachment Drift / Loss| QUAR
    QUAR -->|Pauses & Terminates| VMM
    QUAR -->|Logs Receipts| RING
```

---

## Packet admission flow

```mermaid
flowchart TD
    PKT["Ingress Frame"] --> ETH{EtherType?}

    ETH -->|ARP (0x0806)| ARP{Request / Reply<br/>42B or 60B pad?}
    ARP -->|Yes| PASS["PASS: Admitted"]
    ARP -->|No| D_ARP["DROP: Malformed ARP"]

    ETH -->|IPv4 (0x0800)| IP{IPv4 Header Checks<br/>IHL=5, No Options<br/>MF=0, FragOffset=0<br/>No GSO, Valid Csum?}
    ETH -->|Other / VLAN| D_ETH["DROP: Non-IPv4 or VLAN"]

    IP -->|No| D_IP["DROP: Frag / Option / GSO / Csum"]
    IP -->|Yes| L4{Protocol?}

    L4 -->|TCP (6)| TCP{Port > 0?<br/>Length Valid?}
    L4 -->|UDP (17)| UDP{Dst Port > 0?<br/>Length Valid?}
    L4 -->|Other| D_PROTO["DROP: Unsupported Protocol"]

    TCP -->|Yes| PASS
    TCP -->|No| D_TCP["DROP: Bad TCP Ports/Length"]
    UDP -->|Yes| PASS
    UDP -->|No| D_UDP["DROP: Bad UDP Port/Length"]
```

---

## Supervisor lifecycle and quarantine

```mermaid
stateDiagram-v2
    [*] --> PREFLIGHT: Read admission.json
    PREFLIGHT --> ATTACHING: Check Object Hash & Kernel Release
    ATTACHING --> VERIFIED: Loader attaches clsact to DOWN interface
    VERIFIED --> RUNNING: Drop privileges (Non-root UID/GID)
    
    state RUNNING {
        [*] --> COHERENT: Status matches interface 4-tuple ID
        COHERENT --> COHERENT: Regular poll OK
    }
    
    RUNNING --> QUARANTINE: ID Mismatch or Filter Disappears
    
    state QUARANTINE {
        [*] --> SIGSTOP: Pause VMM process group
        SIGSTOP --> LINK_DOWN: Bring TAP interface DOWN
        LINK_DOWN --> SIGKILL: Terminate VMM process group
    }
    
    QUARANTINE --> EXIT: Flush receipts (200ms timeout)
    RUNNING --> EXIT: Normal VMM exit
    EXIT --> [*]
```

---

## Components

| Component | Files | Role |
|---|---|---|
| **Packet filter** | [`policy.h`](policy.h), [`csumguard_tc.bpf.c`](csumguard_tc.bpf.c) | Header-only classifier at TC ingress. Permits standard TCP, UDP, and ARP. Drops fragments, options, GSO, and VLANs. 26 per-CPU counters track reasons. |
| **Checksum detector** | [`detect_policy.h`](detect_policy.h), [`csumguard_detect.bpf.c`](csumguard_detect.bpf.c) | Optional `fentry` probe tracking `CHECKSUM_PARTIAL` packets in the kernel. Increments counters on suspicious offsets. Never blocks. |
| **Loader** | [`loader.c`](loader.c) | Validates file paths from `/` to prevent symlink attacks. Verifies SHA-256 digests, ensures interface is `DOWN`, and attaches `clsact`. |
| **VMM launcher** | [`launch.c`](launch.c), [`launch_policy.h`](launch_policy.h) | Validates operator evidence, drops privileges to non-root UID/GID, starts the VMM, and monitors attachment. Pauses and kills the VM if the filter drops. |
| **Receipt ledger** | [`launch.c`](launch.c) | Asynchronous thread writing FIPS 180-4 SHA-256 hash-chained JSONL records. 64-slot ring buffer prevents disk stalls. |

---

## Quick start

### 1. Build and test offline

```bash
make EGRESS_MTU=1500 all
make test
```

### 2. Attach the filter

Stage the object in a root-owned directory (`/opt/csumguard`), ensure the TAP interface is `DOWN`, and attach:

```bash
/opt/csumguard/csumguard_loader attach tap0 /opt/csumguard/csumguard_tc.bpf.o <EXPECTED_SHA256>
/opt/csumguard/csumguard_loader status tap0 <IFINDEX> <NETNS_INODE> <PROG_ID>
```

### 3. Launch with supervision

Fill out `/etc/csumguard/admission.json` and start the VMM under `csumguard_launch`:

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

---

## Verification

```bash
# Verify all source and evidence hashes
shasum -a 256 -c SHA256SUMS

# Run offline test suite
make test

# Run AddressSanitizer and UndefinedBehaviorSanitizer
clang -std=c11 -O1 -g -fsanitize=address,undefined -DEGRESS_MTU=1500 -I. tests/test_policy.c -o /tmp/p_asan && /tmp/p_asan
clang -std=c11 -O1 -g -fsanitize=address,undefined -I. tests/test_launch.c -lpthread -o /tmp/l_asan && /tmp/l_asan
clang -std=c11 -O1 -g -fsanitize=address,undefined tests/send_frame.c -o /tmp/f_asan && /tmp/f_asan --self-test
```

---

## Repository layout

```shell
policy.h                  Packet admission parser and reason codes
detect_policy.h           Checksum partial predicate
launch_policy.h           Admission validator, 6D vector state, and SHA-256
csumguard_tc.bpf.c        TC ingress eBPF program
csumguard_detect.bpf.c    fentry/skb_checksum_help probe
loader.c                  libbpf loader and status reporter
launch.c                  VMM supervisor, quarantine engine, and receipt writer
tests/                    Offline C11 test suites and frame generator
testbed.sh                Lab veth test harness
docs/                     Runbook, admission spec, and CVE references
evidence/                 Verification logs and test records
promotion-gates.yaml      Gate statuses and target requirements
```

---

## Boundaries that matter

1. **Private metadata.** The filter checks L2/L3/L4 packet headers. Small valid TCP/UDP packets can still carry malformed checksum metadata until the host kernel or virtio backend checks them.
2. **Unsupported protocols.** IPv6, ICMP, IP options, and fragmentation are dropped. Guest MTU must match the host route MTU since Path MTU Discovery is disabled.
3. **Supervisor scope.** The launcher is a polling process. A VM process that escapes its session process group needs an external cgroup manager.

---

## Documentation

- [VALIDATION.md](VALIDATION.md) — Test matrix, MTU boundary results, and verification status
- [GATES.md](GATES.md) — Security audit gates and remediated bug list
- [docs/RUNBOOK.md](docs/RUNBOOK.md) — Deployment, verification, and quarantine runbook
- [docs/ADMISSION.md](docs/ADMISSION.md) — Admission schema, 6D vector state, and receipts
- [docs/references.md](docs/references.md) — Upstream Linux kernel commits and CVE notes

---

## License

GPL-2.0. See [LICENSE](LICENSE).
