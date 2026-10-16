# Test suites

Describes the offline C11 test binaries and fixtures.

---

## Test architecture

```mermaid
flowchart TD
    subgraph TestPolicy["tests/test_policy.c"]
        TP_PARSE["policy.h Parser Tests<br/>(IPv4, TCP, UDP, ARP)"]
        TP_LEG["legacy_tc_body.h<br/>(Original behavior regressions)"]
        TP_DET["detect_policy.h<br/>(16-bit wrap-around guards)"]
    end

    subgraph TestLaunch["tests/test_launch.c"]
        TL_APP["launch_policy.h<br/>(Admission JSON validator)"]
        TL_VEC["Vector State Engine<br/>(6D transitions)"]
        TL_OPS["Mock OS Boundary<br/>(struct csg_launch_ops)"]
        TL_QUAR["Quarantine Tests<br/>(Pause, disconnect, kill)"]
        TL_RING["Receipt Writer<br/>(Full-queue drain and stalls)"]
    end

    subgraph SendFrame["tests/send_frame.c"]
        SF_SELF["--self-test<br/>(Validates 6 test frames)"]
        SF_HEX["--dump-hex<br/>(Prints hex payload)"]
        SF_SOCK["AF_PACKET raw socket<br/>(Injects to testbed veth)"]
    end
```

---

## Running the tests

```bash
# Run all unit tests
make test

# Run individual test binaries
./build/test_policy
./build/test_launch
./build/send_frame --self-test
```

### Coverage summary

- `test_policy.c` — Exercises `policy.h` and `detect_policy.h` without BPF dependencies. Tests fragmentation flags, TCP options, ARP padding, checksum corruption, and upper-bit protocol truncation.
- `test_launch.c` — Tests `launch_policy.h` and `launch.c` using an injected operations table (`struct csg_launch_ops`). Verifies signal isolation, receipt ring buffer behavior, privilege dropping, and quarantine teardown.
- `send_frame.c` — Generates raw Ethernet frames for lab testing. Includes an offline `--self-test` mode to verify packet structures on any POSIX system.
