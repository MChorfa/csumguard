#!/usr/bin/env bash
# Disposable veth integration fixture only; does not exercise virtio metadata.
set -euo pipefail
cd -- "$(dirname -- "$0")"
if [[ ! -r /proc/self/status ]]; then
    echo 'SKIP: requires CAP_NET_ADMIN, CAP_NET_RAW and CAP_SYS_ADMIN for disposable named netns/BPF' >&2
    exit 77
fi
CAP_EFF_HEX=$(awk '/^CapEff:[[:space:]]*[0-9a-fA-F]+/ { print $2; exit }' /proc/self/status)
REQ_MASK=$(( (1 << 12) | (1 << 13) | (1 << 21) ))
if [[ -z "$CAP_EFF_HEX" ]] || (( (16#$CAP_EFF_HEX & REQ_MASK) != REQ_MASK )); then
    echo 'SKIP: requires CAP_NET_ADMIN, CAP_NET_RAW and CAP_SYS_ADMIN for disposable named netns/BPF' >&2
    exit 77
fi
for tool in ip awk sed od tr sha256sum realpath mktemp; do
    command -v "$tool" >/dev/null || { echo "SKIP: missing $tool" >&2; exit 77; }
done
[[ -x build/csumguard_loader && -x build/send_frame && -f build/csumguard_tc.bpf.o ]] || { echo 'SKIP: run make all first' >&2; exit 77; }
TOKEN=$(od -An -tx1 -N3 /dev/urandom | tr -d ' \n')
if [[ ! "$TOKEN" =~ ^[0-9a-f]{6}$ ]]; then
    echo 'FAIL: unable to generate 6-hex token from /dev/urandom' >&2
    exit 1
fi
NS="csg-test-$TOKEN"
HOST="csgh$TOKEN"
GUEST="csgg$TOKEN"
NS_CREATED=0
LINK_CREATED=0
TMP=$(mktemp -d)
cleanup() {
    if (( LINK_CREATED )); then ip link del "$HOST" 2>/dev/null || true; fi
    if (( NS_CREATED )); then ip netns del "$NS" 2>/dev/null || true; fi
    rm -rf -- "$TMP"
}
trap cleanup EXIT
extract_counter() {
    local file=$1
    local key=$2
    sed -n "s/.*\"${key}\":\([0-9][0-9]*\).*/\1/p" "$file"
}
ip netns add "$NS"
NS_CREATED=1
ip link add "$HOST" type veth peer name "$GUEST"
LINK_CREATED=1
ip link set "$GUEST" netns "$NS"
ip link set dev "$HOST" address 02:00:00:00:00:01 mtu 9000 addrgenmode none
ip netns exec "$NS" ip link set dev "$GUEST" address 02:00:00:00:00:02 mtu 9000 addrgenmode none
OBJ=$(realpath build/csumguard_tc.bpf.o)
SHA=$(sha256sum "$OBJ" | cut -d' ' -f1)
./build/csumguard_loader attach "$HOST" "$OBJ" "$SHA" > "$TMP/identity.json"
read -r INDEX NETNS PROG < <(
    sed -n 's/.*"ifindex":\([0-9][0-9]*\),"netns_inode":\([0-9][0-9]*\),"prog_id":\([0-9][0-9]*\).*/\1 \2 \3/p' "$TMP/identity.json"
)
if [[ -z "${INDEX:-}" || -z "${NETNS:-}" || -z "${PROG:-}" ]]; then
    echo 'FAIL: malformed identity JSON from csumguard_loader' >&2
    exit 1
fi
status() { ./build/csumguard_loader status "$HOST" "$INDEX" "$NETNS" "$PROG"; }
ip link set dev "$HOST" up
ip netns exec "$NS" ip link set dev "$GUEST" up
for CASE in udp:pass_ipv4 arp:pass_arp oversize:drop_mtu first-fragment:drop_fragment later-fragment:drop_fragment ipv6:drop_l2; do
    KIND=${CASE%%:*}
    REASON=${CASE#*:}
    status > "$TMP/before.json"
    ip netns exec "$NS" ./build/send_frame "$GUEST" "$KIND"
    status > "$TMP/after.json"
    BEFORE=$(extract_counter "$TMP/before.json" "$REASON")
    AFTER=$(extract_counter "$TMP/after.json" "$REASON")
    if [[ -z "$BEFORE" || -z "$AFTER" ]]; then
        echo "FAIL: missing counter $REASON in status output" >&2
        exit 1
    fi
    DELTA=$(( AFTER - BEFORE ))
    if (( DELTA != 1 )); then
        echo "FAIL live veth: $KIND $REASON delta=$DELTA before=$BEFORE after=$AFTER" >&2
        exit 1
    fi
    echo "PASS live veth: $KIND $REASON +1"
done
# An incorrect program identity must fail with a nonzero exit status.
if ./build/csumguard_loader status "$HOST" "$INDEX" "$NETNS" 4294967295 > /dev/null 2>&1; then
    echo 'FAIL: stale program identity accepted' >&2
    exit 1
fi
echo 'PASS live veth policy checks; VMM/TAP and CVE validation remain separate'
