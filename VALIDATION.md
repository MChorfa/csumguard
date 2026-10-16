# Validation receipt

Summary of test results, memory safety checks, and remaining target gates.

---

## Verification pipeline

```mermaid
flowchart TD
    subgraph Offline["Offline Verification: PASSING"]
        T1["Policy & Parser Checks<br/>(16,553 checks in test_policy)"]
        T2["Supervisor & Quarantine Checks<br/>(25 test suites in test_launch)"]
        T3["Raw Frame Generator<br/>(6 fixtures in send_frame)"]
        T4["Sanitizer Suite<br/>(AddressSanitizer + UBSan Clean)"]
        T5["MTU Boundary Matrix<br/>(MTUs 68, 1280, 1500, 9000, 65535)"]
        T6["Integrity Manifest<br/>(All files match SHA256SUMS)"]
    end

    subgraph Target["Target Host Verification: BLOCKED"]
        B1["Live BPF Verifier Load on Kernel"]
        B2["Live veth Fixture (testbed.sh)"]
        B3["Real VMM + TAP Quarantine Test"]
        B4["Vendor Fixed-Kernel Backport Proof"]
    end

    Offline ==>|Prerequisites passed| Target
```

---

## Verification results

| Check | Command | Status | Notes |
|---|---|---|---|
| **Unit tests** | `make test` | **PASS** | 16,553 packet assertions, 25 supervisor suites, 6 frame tests |
| **Sanitizers** | `-fsanitize=address,undefined` | **PASS** | 0 leaks, 0 undefined behavior errors |
| **MTU matrix** | `EGRESS_MTU` $\in \{68, 1280, 9000, 65535\}$ | **PASS** | All boundary configs pass |
| **Shell syntax** | `bash -n testbed.sh` | **PASS** | Clean syntax |
| **Manifest** | `shasum -a 256 -c SHA256SUMS` | **PASS** | 100% hash integrity |
| **Live lab veth** | `sudo bash testbed.sh` | **SKIPPED** | Exits 77 on unprivileged host |
| **Real VMM/TAP** | Target testbed | **BLOCKED** | Requires target Linux hypervisor |

---

## What was verified offline

1. **Parser invariants.** The classifier in [`policy.h`](policy.h) strictly accepts in-profile TCP/UDP and ARP frames. It rejects IPv4 options, fragmentation (`MF=1` or `offset > 0`), GSO, VLAN tags, and checksum corruption.
2. **Supervisor containment.** [`test_launch.c`](tests/test_launch.c) tests 25 scenarios using mock OS operations:
   - Quarantine on filter disappearance or interface change.
   - Signal masking during shutdown.
   - Non-zero exit code if cleanup fails.
   - Non-blocking receipt writes under disk stalls.
3. **Detector safety.** [`detect_policy.h`](detect_policy.h) tests 16-bit wrap-around and boundary conditions for `CHECKSUM_PARTIAL`.
