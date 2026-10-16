# Reference register

Verified on 2026-10-16. These are technical evidence sources, not compliance standards. No source establishes that a particular deployed host is patched.

| ID | Title / publisher | Version or date | Section | Claim supported | Evidence type / verification | URL |
|---|---|---|---|---|---|---|
| R01 | NVD CVE-2026-99999 — NIST; Linux CNA metrics | 2026-10-15 | Metrics | CNA 9.3; NVD has no independent score | CNA record displayed by NVD; retrieved search text | [source](https://nvd.nist.gov/vuln/detail/cve-2026-99999) |
| R02 | CVE-2026-99999 — Red Hat Product Security | current 2026-10-16 | CVSS breakdown | 8.8 with PR:L; preliminary vendor assessment | vendor security advisory; retrieved search text | [source](https://access.redhat.com/security/cve/cve-2026-99999) |
| R03 | CVE-2026-99999 — Canonical | updated 2026-10-15 | Status; linux/noble and relevant flavors | 24.04 needs evaluation; not confirmed fixed | distribution security tracker; opened | [source](https://ubuntu.com/security/CVE-2026-99999) |
| R04 | ipv4: validate checksum_start before completing checksum — Linux upstream | commit 6785011f8b16abf40b1e9d8b2e332232b3e68822 | include/net/ip.h and five consumers | sink-side check; broader input validation remains separate | accepted source change; diff opened | [source](https://github.com/torvalds/linux/commit/6785011f8b16abf40b1e9d8b2e332232b3e68822) |
| R05 | PwnEscape: Guest-to-Host KVM Escape — PWNAI Research / Paulos Yibelo | accessed 2026-10-16 | Parts 04 and 05 | reassembly in leak case; owned-host execution claim distinct from production | original researcher disclosure; opened; not independently reproduced | [source](https://www.pwn.ai/blog/pwnescape) |
| R06 | Checksum Offloads — Linux kernel documentation | accessed 2026-10-16 | TX Checksum Offload | offset-driven writes and software fallback | implementation documentation; opened | [source](https://docs.kernel.org/networking/checksum-offloads.html) |
| R07 | LSM BPF Programs — Linux kernel documentation | accessed 2026-10-16 | Structure; attachment | BPF enforcement at existing LSM hooks | implementation documentation; opened | [source](https://docs.kernel.org/bpf/prog_lsm.html) |
| R08 | more virtio-net csum hardening v2 0/7 — Linux networking maintainers | 2026-10-15 | patch-series title | additional input validation under discussion | proposed patch series; search discovery only; merge status unverified | [source](https://lkml.iu.edu/2610.1/18264.html) |
| R09 | CVE-2026-99999: ipv4: validate checksum_start before completing checksum — Linux CVE team | 2026-10-15 | affected/fixed releases | 5.10.272 fixed branch evidenced in search | CNA announcement; search excerpt only; complete branch list not independently retrieved | [source](https://lists.openwall.net/linux-cve-announce/2026/10/15/2) |
