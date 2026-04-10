#!/bin/bash

# Configuration
rmmod igc;modprobe igc
IFACES=("enp86s0" "enp87s0")  # Original interface names
sleep 1
for INDEX in "${!IFACES[@]}"; do
    ORIG_IFACE="${IFACES[$INDEX]}"
    PF_NAME="eth${INDEX}"
    PORT_NUM=$((INDEX + 1))
    IPADDR="${BASE_IP}.${SUBNET}.${SYSID}/16"
    SUBNET=$((SUBNET + 1))

    # Rename physical interface only if not already renamed
    if ! ip link show "$PF_NAME" &>/dev/null; then
        echo "Renaming $ORIG_IFACE to $PF_NAME"
        ip link set "$ORIG_IFACE" down
        ethtool -X "$ORIG_IFACE" equal 1
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
