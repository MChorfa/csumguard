# Test scope

`test_policy.c` runs the exact parser in `policy.h` through a native adapter.
`legacy_tc_body.h` preserves the original function body with only its function
and context type renamed; kernel helper calls are replaced with native fixtures.
Its input source archive SHA-256 is
`13d8094bb33561f3f62cc4e853032bdb5641a8ea473239c29d3c58ccd3c5b3d9`.

These tests include positive controls, legacy-acceptance regressions, a truncation
sweep and every nonzero fragment offset/MF combination. The detector predicate
has state-union guards tested separately; CO-RE reads and BPF attachment are not
exercised natively. Test counts include loop assertions and are not a count of
independent exploit variants.

`test_launch.c` tests the pure admission/vector-state kernel in `launch_policy.h`
and real `csg_launch_run()` orchestration in `launch.c` with OS/network boundaries
injected via `struct csg_launch_ops`. It includes FIPS SHA-256 vectors, hash-chain
verification, a stalled receipt writer during protection loss, full-queue close
drain, and signal-masked quarantine regressions. It does not execute a real VMM,
change host UID/GID or load BPF.

`send_frame.c` supports the optional disposable veth fixture (`AF_PACKET` raw
socket on Linux) and provides `--self-test` to validate all 6 fixture frames
against `policy.h`. These are ordinary packet-policy inputs with no virtio
metadata or kernel exploitation primitive.
