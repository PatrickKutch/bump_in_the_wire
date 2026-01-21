#!/bin/bash
# Container runner script for bitw_xdp AF_XDP forwarder

set -e

if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: This script requires root privileges"
    echo "   Run with: sudo $0"
    exit 1
fi

if [ $# -lt 2 ]; then
    echo "🚀 bitw_xdp Container Runner"
    echo "============================"
    echo ""
    echo "Usage: $0 <interface_A> <interface_B> [additional_options]"
    echo ""
    echo "Examples:"
    echo "  sudo $0 PF0 PF1"
    echo "  sudo $0 PF0 PF1 --cpu-a 2 --cpu-b 3"
    echo "  sudo BUMP_VERBOSE=1 $0 eth0 eth1"
    echo ""
    echo "Available interfaces:"
    ip -o link show | awk -F': ' '{print "  ", $2}' | grep -v lo
    echo ""
    exit 1
fi

INTERFACE_A=$1
INTERFACE_B=$2
shift 2

echo "🔧 Cleaning up any existing XDP programs..."
ip link set dev "$INTERFACE_A" xdp off 2>/dev/null || echo "  (no existing program on $INTERFACE_A)"
ip link set dev "$INTERFACE_B" xdp off 2>/dev/null || echo "  (no existing program on $INTERFACE_B)"

echo "🚀 Starting bitw_xdp container..."
echo "   Forwarding: $INTERFACE_A ↔ $INTERFACE_B"
if [ $# -gt 0 ]; then
    echo "   Additional options: $*"
fi
echo ""

# Run the container with all required mounts and settings
exec docker run \
    --privileged \
    --network=host \
    --rm \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /sys:/sys \
    -v /proc:/proc \
    bitw_xdp:docker-only \
    "$INTERFACE_A" "$INTERFACE_B" "$@"