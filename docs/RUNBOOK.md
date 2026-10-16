# Lab runbook — no production promotion yet

1. Record the exact running kernel package/flavor, VMM/backend, TAP queues,
   bridge/routing/netfilter/XFRM/NFQUEUE and offload/tunnel configuration. Establish
   fixed-kernel activation using the distributor's current backport record.
2. Build the candidate on the target toolchain. Record compiler/libbpf versions,
   object digest, loader digest and target BTF identity. Run native tests and the
   disposable veth fixture. Preserve actual output and skipped tests separately.
3. Establish backend rejection of malformed guest checksum metadata. Validate
   real virtio→backend→TAP behavior with synthetic data on an isolated owned host.
   The veth fixture does not cover this. Verify legitimate guest workloads.
4. Stage immutable root-owned files in a dedicated deployment directory and
   root-private receipt directory. Reserve exclusive TC ownership and create
   the guest TAP while DOWN. Prepare a nonroot VMM account with only required
   device access; supplementary groups and inherited environment are cleared.
5. Fill the JSON appraisal below from actual evidence and independent appraisal.
   Kernel release and guard digest must match. The reference strings identify
   evidence to review; this launcher does not fetch/appraise/sign those records.
6. Run the experimental wrapper with an explicit VMM command on the lab host:

```text
/opt/csumguard/csumguard_launch \
  --interface tapLAB \
  --loader /opt/csumguard/csumguard_loader \
  --object /opt/csumguard/csumguard_tc.bpf.o \
  --evidence /opt/csumguard/admission.json \
  --receipt /var/lib/csumguard/receipts/unique-run.jsonl \
  --uid VMM_UID --gid VMM_GID -- /absolute/VMM [arguments]
```

The wrapper creates the receipt exclusively; it never overwrites a prior run.
It enables the already-existing TAP only after checks and leaves its guard
attached on shutdown. A new run on the same clsact is intentionally refused;
inspect and reset that lab interface under controlled ownership. VM state,
storage and cgroup configuration are provided by the external VMM controller.

7. Exercise interface deletion, attachment replacement, controller termination,
   logging stalls, multiqueue/hotplug and route changes. Establish independent
   disconnect ownership for supervisor failure. A poller alone is insufficient.
8. Measure baseline/candidate throughput, packets/s, p99 latency, CPU and memory.
   Stop promotion on unsupported paths, unexplained errors, evidence loss or
   unguarded fallback. Roll back only to a validated fixed-kernel configuration,
   or keep the workload disconnected.

## Appraisal template (JSON consumed by the launcher)

```json
{
  "schema_version": "csumguard-admission/v1",
  "running_kernel": "REPLACE_WITH_RUNNING_RELEASE",
  "guard_sha256": "REPLACE_WITH_ACCEPTED_OBJECT_DIGEST",
  "kernel_package": "REPLACE_WITH_EXACT_PACKAGE_BUILD",
  "fix_reference": "REPLACE_WITH_VENDOR_BACKPORT_RECORD",
  "validation_receipt": "REPLACE_WITH_TARGET_VALIDATION_RECEIPT",
  "kernel_patch_verified": false,
  "network_path_validated": false,
  "backend_metadata_validated": false,
  "compatibility_validated": false,
  "exclusive_tc_owner": false
}
```

Do not use an invented fixed version, provisional tracker status or installed
but inactive package as fixed-kernel evidence. Record authority and appraisal
outside this candidate before approving those fields.
