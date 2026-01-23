#!/bin/bash

# Configuration script for filter testing with veth pair and namespace
# Sets up PF0 for traffic generation and veth pair for filtered traffic delivery

# Configuration
rmmod ice;modprobe ice
NUM_VFS=4
IFACES=("enp24s0f0np0" "enp24s0f1np1")  # Original interface names
CLEAN_NS="clean-endpoint"
VETH_HOST_SIDE="veth_host_side"
VETH_NS_SIDE="veth_ns_side"

HOSTNAME=$(hostname)
SYSID=""

# Clean up existing setup
ip netns del $CLEAN_NS 2>/dev/null
ip link del $VETH_HOST_SIDE 2>/dev/null

# Reload ice driver
rmmod ice;modprobe ice
sleep 2

# Determine system ID based on hostname
if [[ "$HOSTNAME" == "npg-svr-32" ]]; then
    SYSID="32"
    TRAFFIC_GEN_IP="100.100.100.10"
elif [[ "$HOSTNAME" == "npg-svr-33" ]]; then
    SYSID="33"
    TRAFFIC_GEN_IP="100.100.100.10"
else
    echo "Unknown hostname: $HOSTNAME"
    echo "Defaulting to .10 for traffic generator IP"
    TRAFFIC_GEN_IP="100.100.100.10"
fi

echo "=== Configuring Physical Interfaces ==="

# Rename and configure physical interfaces
for INDEX in "${!IFACES[@]}"; do
    ORIG_IFACE="${IFACES[$INDEX]}"
    PF_NAME="PF${INDEX}"

    # Rename physical interface only if not already renamed
    if ! ip link show "$PF_NAME" &>/dev/null; then
        echo "Renaming $ORIG_IFACE to $PF_NAME"
        ip link set "$ORIG_IFACE" down
        ethtool -L "$ORIG_IFACE" combined 1
        ip link set "$ORIG_IFACE" name "$PF_NAME"
        ip link set "$PF_NAME" up
    else
        echo "$ORIG_IFACE is already named $PF_NAME"
    fi

    # Set promiscuous mode for AF_XDP
    ip link set "$PF_NAME" promisc on
    
    # Disable checksum offload to prevent corruption during AF_XDP forwarding
    echo "Disabling checksum offload on $PF_NAME"
    ethtool -K "$PF_NAME" tx-checksum-ip-generic off tx-checksum-ipv4 off tx-checksum-ipv6 off 2>/dev/null || echo "Some checksum offload options not available on $PF_NAME"
done

# Configure PF0 for traffic generation (in main namespace)
echo "Configuring PF0 for traffic generation with IP $TRAFFIC_GEN_IP"
ip addr flush dev PF0
ip addr add $TRAFFIC_GEN_IP/24 dev PF0
ip link set PF0 up

echo "=== Creating veth pair and clean traffic namespace ==="

# Create veth pair
echo "Creating veth pair: $VETH_HOST_SIDE <-> $VETH_NS_SIDE"
ip link add $VETH_HOST_SIDE type veth peer name $VETH_NS_SIDE

# Disable checksum offload for veth interface to prevent corruption
# When AF_XDP forwards packets from E810 hardware (with hardware checksums) to veth software
# interfaces, checksum fields can become corrupted. Disabling checksum offload forces the
# kernel to calculate correct checksums in software for TCP/IP packets.
echo "Disabling checksum offload for $VETH_HOST_SIDE"
ethtool -K $VETH_HOST_SIDE tx-checksum-ip-generic off tx-checksum-ipv4 off tx-checksum-ipv6 off 2>/dev/null || echo "Some checksum offload options not available on $VETH_HOST_SIDE"

# Create namespace for clean traffic
echo "Creating namespace: $CLEAN_NS"
ip netns add $CLEAN_NS

# Move veth1 to namespace and configure
echo "Moving $VETH_NS_SIDE to namespace $CLEAN_NS"
ip link set $VETH_NS_SIDE netns $CLEAN_NS
ip netns exec $CLEAN_NS ip link set $VETH_NS_SIDE name eth0
ip netns exec $CLEAN_NS ip addr add 100.100.100.100/24 dev eth0
ip netns exec $CLEAN_NS ip link set eth0 up
ip netns exec $CLEAN_NS ip link set lo up

# Disable checksum offload on namespace side of veth pair
# This prevents TCP checksum corruption when packets transition from AF_XDP hardware processing
# to software veth interfaces. Veth interfaces don't have real hardware checksum engines but can
# still advertise checksum offload, leading to invalid checksums in TCP packets.
echo "Disabling checksum offload on namespace interface (eth0) to prevent TCP corruption"
ip netns exec $CLEAN_NS ethtool -K eth0 tx-checksum-ip-generic off rx-checksumming off tx-checksumming off 2>/dev/null || echo "Some checksum offload options not available on namespace eth0"

ip netns exec $CLEAN_NS netserver

# Configure veth0 in main namespace (for filter output - NO IP ADDRESS)
echo "Configuring $VETH_HOST_SIDE in main namespace (no IP for AF_XDP filtering)"
ip link set $VETH_HOST_SIDE up
ip link set $VETH_HOST_SIDE promisc on

echo "Waiting 3 seconds for namespace setup..."
sleep 3

echo "=== Configuration Summary ==="
echo "Physical interfaces:"
ip -br link show | grep -E "PF[0-1]"
echo ""
echo "PF0 (traffic generator):"
ip -br addr show PF0
echo ""
echo "PF1 (filter input - should have no IP):"
ip -br addr show PF1
echo ""
echo "veth0 (filter output in main namespace - no IP):"
ip -br addr show $VETH_HOST_SIDE
echo ""
echo "Clean traffic namespace ($CLEAN_NS) interfaces:"
ip netns exec $CLEAN_NS ip -br addr
echo ""
echo "=== Ready for Filter Testing ==="
echo "1. Run bitw_filter: PF1 -> veth0 (drops watermarked packets)"
echo "   docker run --privileged --network=host --rm \\"
echo "     -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \\"
echo "     -e BITW_MODE=filter \\"
echo "     bitw_xdp:docker-only PF1 veth0"
echo ""
echo "2. Test from PF0 ($TRAFFIC_GEN_IP) to filtered namespace (100.100.100.100):"
echo "   ping 100.100.100.100  # Should ONLY work through PF1 -> filter -> veth0 -> namespace"
echo "   # Traffic flow: PF0 -> System2 -> PF1 -> filter -> veth0 -> namespace (100.100.100.100)"
echo ""
echo "3. Monitor filtered traffic:"
echo "   ip netns exec $CLEAN_NS tcpdump -i eth0"
echo ""
echo "NOTE: 100.100.100.100 is ONLY reachable through the filter - no direct access from host!"