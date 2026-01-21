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
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY bitw_common.h bitw_common.cpp bitw_sflow.cpp bitw_filter.cpp Makefile ./

# Build both applications
RUN make clean && make

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
COPY Readme.md .

RUN chmod +x bitw_sflow bitw_filter

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
    *)\n\
        echo "❌ Error: Invalid BITW_MODE=$PROGRAM"\n\
        echo "   Valid modes: sflow, filter"\n\
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
if [ $# -lt 2 ]; then\n\
    echo "Usage: docker run --privileged --network=host --rm [-e BITW_MODE=sflow|filter] <image> <netdev_A> <netdev_B> [options]"\n\
    echo ""\n\
    echo "Modes:"\n\
    echo "  BITW_MODE=sflow   S-Flow sampling with TCP watermarking (default)"\n\
    echo "  BITW_MODE=filter  Watermark detection and filtering"\n\
    echo ""\n\
    echo "Examples:"\n\
    echo "  # S-Flow mode (default)"\n\
    echo "  sudo docker run --privileged --network=host --rm <image> eth0 eth1 --sample.sampling 1000 --sample.ethertypes=0x800"\n\
    echo "  # Filter mode"\n\
    echo "  sudo docker run --privileged --network=host --rm -e BITW_MODE=filter <image> eth0 eth1"\n\
    echo "  # CPU pinning"\n\
    echo "  sudo docker run --privileged --network=host --rm <image> eth0 eth1 --cpu-a 2 --cpu-b 4"\n\
    echo ""\n\
    echo "Available interfaces:"\n\
    ip -o link show | awk -F": " "{print \\"  \\", \\$2}" | grep -v lo || echo "  (run with --network=host to see interfaces)"\n\
    echo ""\n\
    $BINARY 2>&1 || true\n\
    exit 1\n\
fi\n\
\n\
echo "🔧 Configuring interfaces..."\n\
ip link set dev "$1" promisc on || echo "⚠️  Warning: Failed to set $1 promiscuous mode"\n\
ip link set dev "$2" promisc on || echo "⚠️  Warning: Failed to set $2 promiscuous mode"\n\
\n\
echo "🌐 Starting $DESCRIPTION: $1 ↔ $2"\n\
echo "Press Ctrl+C to stop gracefully"\n\
echo "================================================"\n\
exec $BINARY "$@"' > /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

# Mount points for AF_XDP kernel interfaces
VOLUME ["/sys/fs/bpf", "/sys", "/proc"]

ENTRYPOINT ["/app/entrypoint.sh"]
CMD []