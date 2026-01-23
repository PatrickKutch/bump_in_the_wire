# Configuration
rmmod ice;modprobe ice
NUM_VFS=4
IFACES=("enp24s0f0np0" "enp24s0f1np1")  # Original interface names
NS=clean-endpoint

HOSTNAME=$(hostname)
SYSID=""

ip netns del $NS 2>/dev/null

rmmod ice;modprobe ice

for INDEX in "${!IFACES[@]}"; do
    ORIG_IFACE="${IFACES[$INDEX]}"
    PF_NAME="PF${INDEX}"
    PORT_NUM=$((INDEX + 1))
    IPADDR="${BASE_IP}.${SUBNET}.${SYSID}/16"
    SUBNET=$((SUBNET + 1))

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
done

ip addr add 100.100.100.33/24 dev PF0
ip netns add $NS
ip link set PF1 netns "$NS"
ip netns exec "$NS" ip link set PF1 name eth0
ip netns exec "$NS" ip addr add 100.100.100.100/24 dev eth0
echo sleeping 5 seconds to allow namespace setup
sleep 5
ip netns exec "$NS" ip link set eth0 up
ip netns exec "$NS" ip link set lo up
ip netns exec $NS netserver

echo "Host namespace interfaces:"
ip netns exec "$NS" ip -br a

echo PF0 configuration:
ip -br a show PF0
