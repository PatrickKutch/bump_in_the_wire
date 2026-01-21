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
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY bitw_xdp.cpp .

# Build the application
RUN g++ -std=gnu++17 -Wall -O2 bitw_xdp.cpp -o bitw_xdp -lpthread -lxdp -lbpf

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

# Copy binary from builder
COPY --from=builder /app/bitw_xdp .
COPY Readme.md .

RUN chmod +x bitw_xdp

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
echo "🚀 bitw_xdp AF_XDP Packet Forwarder (Docker-only build)"\n\
echo "================================================"\n\
\n\
if [ "$EUID" -ne 0 ]; then\n\
    echo "❌ Error: Root privileges required for AF_XDP access"\n\
    echo "   Run with: --privileged or --cap-add=NET_ADMIN"\n\
    exit 1\n\
fi\n\
\n\
if [ $# -lt 2 ]; then\n\
    echo "Usage: docker run --privileged --network=host --rm <image> <netdev_A> <netdev_B> [options]"\n\
    echo ""\n\
    echo "Examples:"\n\
    echo "  sudo docker run --privileged --network=host --rm <image> eth0 eth1"\n\
    echo "  sudo docker run --privileged --network=host --rm <image> eth0 eth1 --cpu-a 2 --cpu-b 4"\n\
    echo "  sudo docker run --privileged --network=host --rm -e BUMP_VERBOSE=1 <image> eth0 eth1"\n\
    echo ""\n\
    echo "Available interfaces:"\n\
    ip -o link show | awk -F": " "{print \\"  \\", \\$2}" | grep -v lo || echo "  (run with --network=host to see interfaces)"\n\
    echo ""\n\
    ./bitw_xdp 2>&1 || true\n\
    exit 1\n\
fi\n\
\n\
echo "🔧 Configuring interfaces..."\n\
ip link set dev "$1" promisc on || echo "⚠️  Warning: Failed to set $1 promiscuous mode"\n\
ip link set dev "$2" promisc on || echo "⚠️  Warning: Failed to set $2 promiscuous mode"\n\
\n\
echo "🌐 Starting bidirectional forwarding: $1 ↔ $2"\n\
echo "Press Ctrl+C to stop gracefully"\n\
echo "================================================"\n\
exec ./bitw_xdp "$@"' > /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

# Mount points for AF_XDP kernel interfaces
VOLUME ["/sys/fs/bpf", "/sys", "/proc"]

ENTRYPOINT ["/app/entrypoint.sh"]
CMD []