#!/usr/bin/env bash
# ==============================================================================
# csumguard OCI Artifact Packager
#
# Packages csumguard eBPF binaries, C11 loader, supervisor, and governance
# headers as an OCI v1.1 Artifact with cryptographic evidence, SBOM, and
# SLSA provenance attachments using ORAS.
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

LAYOUT_DIR="${ROOT_DIR}/build/oci-layout"
CONFIG_FILE="${ROOT_DIR}/oci/artifact-config.json"
TAG="v0.2.0"
TARGET_REF=""
PUSH_REMOTE=0

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --layout-dir <dir>    Directory for OCI image layout (default: build/oci-layout)
  --tag <tag>           Artifact tag (default: v0.2.0)
  --push <ref>          Push directly to remote OCI registry (e.g. ghcr.io/org/csumguard:v0.2.0)
  -h, --help            Show this help message
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --layout-dir)
            LAYOUT_DIR="$2"
            shift 2
            ;;
        --tag)
            TAG="$2"
            shift 2
            ;;
        --push)
            TARGET_REF="$2"
            PUSH_REMOTE=1
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "[-] Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

command -v oras >/dev/null 2>&1 || {
    echo "[-] Error: 'oras' CLI is required. Install from https://oras.land" >&2
    exit 1
}

echo "[*] Checking repository integrity..."
shasum -a 256 -c SHA256SUMS

echo "[*] Ensuring release binaries are built..."
if [[ ! -f "build/csumguard_tc.bpf.o" || ! -f "build/csumguard_loader" || ! -f "build/csumguard_launch" ]]; then
    make EGRESS_MTU=1500 all
fi

# Clean prior layout if building locally
if [[ "${PUSH_REMOTE}" -eq 0 ]]; then
    rm -rf "${LAYOUT_DIR}"
    mkdir -p "${LAYOUT_DIR}"
    DEST="${LAYOUT_DIR}:${TAG}"
    TARGET_FLAG="--oci-layout"
else
    DEST="${TARGET_REF}"
    TARGET_FLAG=""
fi

echo "[*] Packaging core OCI Artifact (${DEST})..."

LAYERS=(
    "build/csumguard_tc.bpf.o:application/vnd.csumguard.ebpf.layer.v1+binary"
    "build/csumguard_loader:application/vnd.csumguard.loader.v1+elf"
    "build/csumguard_launch:application/vnd.csumguard.supervisor.v1+elf"
    "policy.h:text/x-c"
    "detect_policy.h:text/x-c"
    "launch_policy.h:text/x-c"
    "promotion-gates.yaml:application/vnd.csumguard.policy.v1+yaml"
    "SHA256SUMS:text/plain"
)

if [[ -f "build/csumguard_detect.bpf.o" ]]; then
    LAYERS+=("build/csumguard_detect.bpf.o:application/vnd.csumguard.ebpf.layer.v1+binary")
fi

if [[ "${PUSH_REMOTE}" -eq 0 ]]; then
    oras push --oci-layout "${DEST}" \
        --artifact-type "application/vnd.csumguard.ebpf.v1" \
        --config "${CONFIG_FILE}:application/vnd.csumguard.config.v1+json" \
        "${LAYERS[@]}"
else
    oras push "${DEST}" \
        --artifact-type "application/vnd.csumguard.ebpf.v1" \
        --config "${CONFIG_FILE}:application/vnd.csumguard.config.v1+json" \
        "${LAYERS[@]}"
fi

echo "[*] Attaching Verification Evidence Bundle..."
if [[ "${PUSH_REMOTE}" -eq 0 ]]; then
    oras attach --oci-layout \
        --artifact-type "application/vnd.csumguard.evidence.v1+json" \
        "${DEST}" \
        "evidence/verification.json:application/vnd.csumguard.evidence.v1+json"
else
    oras attach \
        --artifact-type "application/vnd.csumguard.evidence.v1+json" \
        "${DEST}" \
        "evidence/verification.json:application/vnd.csumguard.evidence.v1+json"
fi

echo "[*] Attaching CycloneDX SBOM..."
if [[ "${PUSH_REMOTE}" -eq 0 ]]; then
    oras attach --oci-layout \
        --artifact-type "application/vnd.cyclonedx+json" \
        "${DEST}" \
        "evidence/sbom.cdx.json:application/vnd.cyclonedx+json"
else
    oras attach \
        --artifact-type "application/vnd.cyclonedx+json" \
        "${DEST}" \
        "evidence/sbom.cdx.json:application/vnd.cyclonedx+json"
fi

echo "[*] Attaching SLSA v1.0 Provenance..."
if [[ "${PUSH_REMOTE}" -eq 0 ]]; then
    oras attach --oci-layout \
        --artifact-type "application/vnd.in-toto+json" \
        "${DEST}" \
        "evidence/provenance.slsa.json:application/vnd.in-toto+json"
else
    oras attach \
        --artifact-type "application/vnd.in-toto+json" \
        "${DEST}" \
        "evidence/provenance.slsa.json:application/vnd.in-toto+json"
fi

echo "[+] OCI Artifact and Attachments generated successfully!"
echo "[*] Discovering artifact graph:"
if [[ "${PUSH_REMOTE}" -eq 0 ]]; then
    oras discover --oci-layout "${DEST}"
else
    oras discover "${DEST}"
fi
