#!/bin/bash

# Configuration
rmmod ice;modprobe ice
NUM_VFS=4
IFACES=("enp24s0f0np0" "enp24s0f1np1")  # Original interface names

HOSTNAME=$(hostname)
SYSID=""

SUBNET=200
BASE_IP="100.100"
if [[ "$HOSTNAME" == "npg-svr-32" ]]; then
    SYSID="32"

elif [[ "$HOSTNAME" == "npg-svr-33" ]]; then
    SYSID="33"
else
    echo "Unknown hostname: $HOSTNAME"
    exit 1
fi

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

    # echo "Configuring $PF_NAME with IP $IPADDR"

    # # Assign IP
    # ip addr flush dev "$PF_NAME"
    # ip addr add "$IPADDR" dev "$PF_NAME"
    ip link set "$PF_NAME" up
    ip link set "$PF_NAME" promisc on

   
done
