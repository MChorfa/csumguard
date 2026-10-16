# Admission and containment contract

The implemented startup order is: reject incomplete operator appraisal; bind the
object digest and running kernel release; attach on the DOWN interface; verify
identity; enable the interface; recheck; launch a nonroot VMM; monitor identity.
The netns inode, ifindex and program ID form the runtime check identity. The
object digest binds the source-independent loaded byte snapshot, not a signature.

The operator must exclusively own TC policy on the interface. No other controller
may add earlier bypasses, redirect around it, replace the qdisc, delete/recreate
the interface or expose alternate ingress paths. A polling check of one filter
cannot prove exclusivity. The supplied gate cannot enforce this assumption.
It also cannot appraise private checksum metadata; the backend/kernel still must.

All launch/evidence directories must be root-owned and not writable by group or
others. Ancestor directories are walked with `openat(..., O_NOFOLLOW)` and leaf
files must have link count 1 (`st_nlink == 1`). Avoid shared writable directories,
including /tmp, for staged executables or receipts. The object file is checked
again by the loader using an exact byte snapshot with post-read EOF and `fstat`
verification. No raw packets, payloads, credentials or full VMM command line are
recorded.

Receipt messages are limited to 16 KiB each and a ring buffer of 64 records. A
background pthread writer performs file I/O. Writer errors or overflow observed
during supervision cause quarantine. Final drain waits at most 0.2 seconds on a
monotonic condition variable; incomplete evidence returns failure and cannot
support an assurance claim. Blocking filesystem I/O cannot hold the packet
filter or polling path. Receipts are unsigned, SHA-256 hash-chained JSONL
(`seq`, `prev_sha256`, `entry_sha256`) with 6D vector state (`presence`,
`valence`, `coherence`, `evidence`, `lifecycle`, `epoch`); timestamps are
monotonic for local ordering, not trusted wall-clock attestation.

Protection-loss response blocks asynchronous termination signals, pauses the
launched process group (`SIGSTOP`), attempts to set the same interface down,
and kills the process group (`SIGKILL`). Disconnect is refused if the name now
refers to another ifindex. A failed disconnect on quarantine or normal exit is
recorded and forces nonzero exit status; there is no automatic unrestricted
fallback. Process groups are not a replacement for cgroup containment of
daemonizing VMM descendants. Signals/commands themselves can fail; an
independent platform controller must own final stop/disconnect.

Production acceptance additionally requires: activated fixed-kernel build and
backport evidence; backend descriptor validation; full network-path inventory;
real VMM/TAP testing of malformed metadata and positive controls; authority to
prevent protection removal; supervisor-crash and cgroup lifecycle integration;
route/MTU change control; measured performance; and an independently appraised
receipt. None of these is established by the native tests.
