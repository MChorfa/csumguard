# syntax=docker/dockerfile:1
# Multi-stage build for csumguard v0.2.0
# Produces verified OCI artifacts: csumguard_loader, csumguard_launch, and csumguard_tc.bpf.o

FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Compile and verify all C11 and eBPF binaries
RUN make clean && \
    make EGRESS_MTU=1500 all && \
    make test && \
    shasum -a 256 -c SHA256SUMS

# Minimal distribution stage
FROM scratch AS artifact

LABEL org.opencontainers.image.title="csumguard" \
      org.opencontainers.image.description="Restricted eBPF TC ingress guard and C11 VMM supervisor for CVE-2026-99999" \
      org.opencontainers.image.version="0.2.0" \
      org.opencontainers.image.licenses="GPL-2.0" \
      org.opencontainers.image.source="https://github.com/MChorfa/csumguard"

COPY --from=builder /src/build/csumguard_loader /opt/csumguard/csumguard_loader
COPY --from=builder /src/build/csumguard_launch /opt/csumguard/csumguard_launch
COPY --from=builder /src/build/csumguard_tc.bpf.o /opt/csumguard/csumguard_tc.bpf.o
COPY --from=builder /src/SHA256SUMS /opt/csumguard/SHA256SUMS
COPY --from=builder /src/LICENSE /opt/csumguard/LICENSE

VOLUME /opt/csumguard
ENTRYPOINT ["/opt/csumguard/csumguard_loader"]
CMD ["--help"]
