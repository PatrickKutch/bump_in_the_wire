#!/bin/bash
# Container runner script for bitw AF_XDP programs

set -e

# Auto-detect container runtime (prefer podman, fallback to docker)
if command -v podman >/dev/null 2>&1; then
    CONTAINER_RUNTIME="podman"
    CONTAINER_IMAGE="bitw_xdp:docker-only"
elif command -v docker >/dev/null 2>&1; then
    CONTAINER_RUNTIME="docker"
    CONTAINER_IMAGE="bitw_xdp:docker-only"
else
    echo "❌ Error: Neither podman nor docker is installed"
    echo "   Please install either podman or docker to continue"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "❌ Error: This script requires root privileges"
    echo "   AF_XDP operations need root access for:"
    echo "   - Creating XDP sockets"
    echo "   - Binding to network interfaces" 
    echo "   - Accessing BPF filesystem"
    echo ""
    if [ "$CONTAINER_RUNTIME" = "podman" ]; then
        echo "   For podman: Run with sudo or as root user"
        echo "   Example: sudo $0 $*"
    else
        echo "   For docker: Run with sudo"
        echo "   Example: sudo $0 $*"
    fi
    exit 1
fi

PROGRAM_MODE="sflow"  # Default mode

# Parse mode option if provided
if [ "$1" = "--mode" ] && [ $# -ge 2 ]; then
    PROGRAM_MODE="$2"
    shift 2
fi

# Validate arguments based on mode
if [ "$PROGRAM_MODE" = "afx_tx" ]; then
    if [ $# -lt 3 ]; then
        echo "🚀 bitw AF_XDP Container Runner"
        echo "==============================="
        echo ""
        echo "Container runtime: $CONTAINER_RUNTIME"
        echo ""
        echo "Usage (afx_tx mode): $0 --mode afx_tx <interface> <dest_mac> <interval_ms> [additional_options]"
        echo ""
        echo "AFX_TX Mode - Standalone AF_XDP TX Test Program:"
        echo "  <interface>   Network interface (e.g., eth0)"
        echo "  <dest_mac>    Destination MAC address (e.g., aa:bb:cc:dd:ee:ff)"
        echo "  <interval_ms> Packet transmission interval in milliseconds"
        echo ""
        echo "Options:"
        echo "  --i226-mode   Use I226-optimized AF_XDP settings"
        echo "  --verbose     Enable verbose packet logging"
        echo ""
        echo "Examples:"
        echo "  sudo $0 --mode afx_tx eth0 aa:bb:cc:dd:ee:ff 1000"
        echo "  sudo $0 --mode afx_tx eth0 aa:bb:cc:dd:ee:ff 500 --i226-mode --verbose"
        echo ""
        echo "Available interfaces:"
        ip -o link show | awk -F': ' '{print "  ", $2}' | grep -v lo
        echo ""
        exit 1
    fi
elif [ $# -lt 2 ]; then
    echo "🚀 bitw AF_XDP Container Runner"
    echo "==============================="
    echo ""
    echo "Container runtime: $CONTAINER_RUNTIME"
    echo ""
    echo "Usage: $0 [--mode sflow|filter] <interface_A> <interface_B> [additional_options]"
    echo ""
    echo "Modes:"
    echo "  sflow   - S-Flow sampling with TCP watermarking (default)"
    echo "  filter  - Watermark detection and filtering"
    echo "  afx_tx  - Standalone AF_XDP TX test program"
    echo ""
    echo "Examples:"
    echo "  sudo $0 PF0 PF1"
    echo "  sudo $0 --mode sflow PF0 PF1 --sample.sampling 1000 --sample.ethertypes=0x800"
    echo "  sudo $0 --mode filter PF0 PF1 --cpu.forwarding 2"
    echo "  sudo $0 --mode afx_tx eth0 aa:bb:cc:dd:ee:ff 1000 --i226-mode"
    echo "  sudo BUMP_VERBOSE=1 $0 eth0 eth1"
    echo ""
    echo "Available interfaces:"
    ip -o link show | awk -F': ' '{print "  ", $2}' | grep -v lo
    echo ""
    exit 1
fi

if [ "$PROGRAM_MODE" != "sflow" ] && [ "$PROGRAM_MODE" != "filter" ] && [ "$PROGRAM_MODE" != "afx_tx" ]; then
    echo "❌ Error: Invalid mode '$PROGRAM_MODE'. Use 'sflow', 'filter', or 'afx_tx'"
    exit 1
fi

INTERFACE_A=$1
if [ "$PROGRAM_MODE" != "afx_tx" ]; then
    INTERFACE_B=$2
    shift 2
    
    echo "🔧 Cleaning up any existing XDP programs..."
    ip link set dev "$INTERFACE_A" xdp off 2>/dev/null || echo "  (no existing program on $INTERFACE_A)"
    ip link set dev "$INTERFACE_B" xdp off 2>/dev/null || echo "  (no existing program on $INTERFACE_B)"
else
    # For afx_tx mode, we only need the first interface
    shift 1
    
    echo "🔧 Cleaning up any existing XDP programs..."
    ip link set dev "$INTERFACE_A" xdp off 2>/dev/null || echo "  (no existing program on $INTERFACE_A)"
fi

echo "🚀 Starting bitw_${PROGRAM_MODE} container..."
echo "   Container runtime: $CONTAINER_RUNTIME"
echo "   Mode: $PROGRAM_MODE"
if [ "$PROGRAM_MODE" = "afx_tx" ]; then
    echo "   Interface: $INTERFACE_A"
else
    echo "   Forwarding: $INTERFACE_A ↔ $INTERFACE_B"
fi
if [ $# -gt 0 ]; then
    echo "   Additional options: $*"
fi
echo ""

# Run the container with all required mounts and settings  
if [ "$CONTAINER_RUNTIME" = "podman" ]; then
    # For podman, check if image exists locally first
    echo "Checking for local image..."
    if ! $CONTAINER_RUNTIME images --format "{{.Repository}}:{{.Tag}}" | grep -q "bitw_xdp:docker-only"; then
        echo "❌ Error: Container image not found in local storage"
        echo ""
        echo "The image needs to be loaded into root's podman storage."
        echo "Please run as root:"
        echo "  1. Load the image: gunzip -c /tmp/bitw_xdp-docker-only.tar.gz | podman load"
        echo "  2. Or copy from user storage: podman save docker.io/library/bitw_xdp:docker-only | podman load --input -"
        echo ""
        echo "Available images in current storage:"
        $CONTAINER_RUNTIME images | grep -E "(REPOSITORY|bitw_xdp)" || echo "  (none found)"
        exit 1
    fi
    
    # Use the full registry path as it appears in podman images
    echo "Running podman as root for AF_XDP privileged operations..."
    echo "Container: docker.io/library/bitw_xdp:docker-only"
    exec $CONTAINER_RUNTIME run \
        --privileged \
        --network=host \
        --rm \
        -v /sys/fs/bpf:/sys/fs/bpf \
        -v /sys:/sys \
        -v /proc:/proc \
        -e BITW_MODE="$PROGRAM_MODE" \
        docker.io/library/bitw_xdp:docker-only \
        $(if [ "$PROGRAM_MODE" != "afx_tx" ]; then echo "$INTERFACE_A" "$INTERFACE_B" "$@"; else echo "$INTERFACE_A" "$@"; fi)
else
    # For docker, use standard approach
    exec $CONTAINER_RUNTIME run \
        --privileged \
        --network=host \
        --rm \
        -v /sys/fs/bpf:/sys/fs/bpf \
        -v /sys:/sys \
        -v /proc:/proc \
        -e BITW_MODE="$PROGRAM_MODE" \
        $CONTAINER_IMAGE \
        $(if [ "$PROGRAM_MODE" != "afx_tx" ]; then echo "$INTERFACE_A" "$INTERFACE_B" "$@"; else echo "$INTERFACE_A" "$@"; fi)
fi