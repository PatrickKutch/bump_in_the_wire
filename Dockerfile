# Docker-only build using Ubuntu 24.04 which has libxdp packages
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies (libxdp is available in Ubuntu 24.04)
RUN apt-get update && apt-get install -y \
    build-essential \
    g++ \
    pkg-config \
    libbpf-dev \
    libxdp-dev \
    linux-headers-generic \
    linux-tools-generic \
    clang \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY bitw_common.h bitw_common.cpp bitw_sflow.cpp bitw_filter.cpp afx_tx.cpp Makefile ./
COPY bitw_sflow_xdp.bpf.c bitw_filter_xdp.bpf.c ./

# Build all applications including standalone afx_tx
RUN make clean && make && make afx_tx

# Runtime stage - use Ubuntu 24.04 for libxdp runtime packages
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libbpf1 \
    libxdp1 \
    iproute2 \
    ethtool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /app/bitw_sflow .
COPY --from=builder /app/bitw_filter .
COPY --from=builder /app/afx_tx .
COPY --from=builder /app/bitw_sflow_xdp.bpf.o .
COPY --from=builder /app/bitw_filter_xdp.bpf.o .
COPY Readme.md .

RUN chmod +x bitw_sflow bitw_filter afx_tx

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Default program is sflow\n\
PROGRAM="${BITW_MODE:-sflow}"\n\
\n\
case "$PROGRAM" in\n\
    sflow)\n\
        BINARY="./bitw_sflow"\n\
        DESCRIPTION="S-Flow Packet Forwarder with TCP Watermarking"\n\
        ;;\n\
    filter)\n\
        BINARY="./bitw_filter"\n\
        DESCRIPTION="Watermark Packet Filter"\n\
        ;;\n\
    afx_tx)\n\
        BINARY="./afx_tx"\n\
        DESCRIPTION="AF_XDP TX Test Program"\n\
        ;;\n\
    *)\n\
        echo "❌ Error: Invalid BITW_MODE=$PROGRAM"\n\
        echo "   Valid modes: sflow, filter, afx_tx"\n\
        exit 1\n\
        ;;\n\
esac\n\
\n\
echo "🚀 $DESCRIPTION (Docker)"\n\
echo "================================================"\n\
\n\
if [ "$EUID" -ne 0 ]; then\n\
    echo "❌ Error: Root privileges required for AF_XDP access"\n\
    echo "   Run with: --privileged or --cap-add=NET_ADMIN"\n\
    exit 1\n\
fi\n\
\n\
# Check arguments based on program mode\n\
if [ "$PROGRAM" = "afx_tx" ]; then\n\
    if [ $# -lt 3 ]; then\n\
        echo "Usage: docker run --privileged --network=host --rm -e BITW_MODE=afx_tx <image> <netdev> <dest_mac> <interval_ms> [options]"\n\
        echo ""\n\
        echo "AFX_TX Mode - Standalone AF_XDP TX Test Program:"\n\
        echo "  <netdev>      Network interface (e.g., eth0)"\n\
        echo "  <dest_mac>    Destination MAC address (e.g., aa:bb:cc:dd:ee:ff)"\n\
        echo "  <interval_ms> Packet transmission interval in milliseconds"\n\
        echo ""\n\
        echo "Options:"\n\
        echo "  --i226-mode   Use I226-optimized AF_XDP settings"\n\
        echo "  --verbose     Enable verbose packet logging"\n\
        echo ""\n\
        echo "Examples:"\n\
        echo "  # Basic AF_XDP TX test"\n\
        echo "  sudo docker run --privileged --network=host --rm -e BITW_MODE=afx_tx <image> eth0 aa:bb:cc:dd:ee:ff 1000"\n\
        echo "  # I226-optimized test with verbose output"\n\
        echo "  sudo docker run --privileged --network=host --rm -e BITW_MODE=afx_tx <image> eth0 aa:bb:cc:dd:ee:ff 1000 --i226-mode --verbose"\n\
        echo ""\n\
        $BINARY 2>&1 || true\n\
        exit 1\n\
    fi\n\
elif [ $# -lt 2 ]; then\n\
    echo "Usage: docker run --privileged --network=host --rm [-e BITW_MODE=sflow|filter|afx_tx] <image> <args>"\n\
    echo ""\n\
    echo "Modes:"\n\
    echo "  BITW_MODE=sflow   S-Flow sampling with TCP watermarking (default)"\n\
    echo "  BITW_MODE=filter  Watermark detection and filtering"\n\
    echo "  BITW_MODE=afx_tx  Standalone AF_XDP TX test program"\n\
    echo ""\n\
    echo "Examples:"\n\
    echo "  # S-Flow mode (default)"\n\
    echo "  sudo docker run --privileged --network=host --rm <image> eth0 eth1 --sample.sampling 1000 --sample.ethertypes=0x800"\n\
    echo "  # Filter mode"\n\
    echo "  sudo docker run --privileged --network=host --rm -e BITW_MODE=filter <image> eth0 eth1"\n\
    echo "  # AFX_TX test mode"\n\
    echo "  sudo docker run --privileged --network=host --rm -e BITW_MODE=afx_tx <image> eth0 aa:bb:cc:dd:ee:ff 1000"\n\
    echo "  # CPU pinning (sflow/filter modes)"\n\
    echo "  sudo docker run --privileged --network=host --rm <image> eth0 eth1 --cpu.forwarding 2 --cpu.return 4"\n\
    echo ""\n\
    echo "Available interfaces:"\n\
    ip -o link show | awk -F": " "{print \\"  \\", \\$2}" | grep -v lo || echo "  (run with --network=host to see interfaces)"\n\
    echo ""\n\
    $BINARY 2>&1 || true\n\
    exit 1\n\
fi\n\
\n\
echo "🔧 Configuring interfaces..."\n\
if [ "$PROGRAM" = "afx_tx" ]; then\n\
    # For afx_tx, only configure the single interface\n\
    ip link set dev "$1" promisc on || echo "⚠️  Warning: Failed to set $1 promiscuous mode"\n\
    echo "🌐 Starting $DESCRIPTION: $1 → $2 (every ${3}ms)"\n\
else\n\
    # For sflow/filter, configure both interfaces\n\
    ip link set dev "$1" promisc on || echo "⚠️  Warning: Failed to set $1 promiscuous mode"\n\
    ip link set dev "$2" promisc on || echo "⚠️  Warning: Failed to set $2 promiscuous mode"\n\
    echo "🌐 Starting $DESCRIPTION: $1 ↔ $2"\n\
fi\n\
echo "Press Ctrl+C to stop gracefully"\n\
echo "================================================"\n\
exec $BINARY "$@"' > /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

# Mount points for AF_XDP kernel interfaces
VOLUME ["/sys/fs/bpf", "/sys", "/proc"]

ENTRYPOINT ["/app/entrypoint.sh"]
CMD []