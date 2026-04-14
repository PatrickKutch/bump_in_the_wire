#!/bin/bash

# Configuration
rmmod igc;modprobe igc
IFACES=("enp86s0" "enp87s0")  # Original interface names
sleep 1
for INDEX in "${!IFACES[@]}"; do
    ORIG_IFACE="${IFACES[$INDEX]}"
    SIMPLE_NAME="eth${INDEX}"

    # Rename physical interface only if not already renamed
    if ! ip link show "$SIMPLE_NAME" &>/dev/null; then
        echo "Renaming $ORIG_IFACE to $SIMPLE_NAME"
        ip link set "$ORIG_IFACE" down
        # set 1 queueueue to ensure all traffic goes to queue 0
        # for enterprise NICs with multiple queues, you can try setting this to 2
        # and then allowing the PTP steering below.  At this time, on my setup it won't work on I226
        ethtool -X "$ORIG_IFACE" equal 1

        # Steer PTP Event messages (UDP 319)
        ###sudo ethtool -N "$ORIG_IFACE" flow-type udp4 dst-port 319 action 1

        # Steer PTP General messages (UDP 320)
        ###sudo ethtool -N "$ORIG_IFACE"flow-type udp4 dst-port 320 action 1

        # Steer Layer 2 PTP
        ###sudo ethtool -N "$ORIG_IFACE" flow-type ether proto 0x88F7 action 1
        
        ip link set "$ORIG_IFACE" name "$SIMPLE_NAME"
        ip link set "$SIMPLE_NAME" up
    else
        echo "$ORIG_IFACE is already named $SIMPLE_NAME"
    fi

    ip link set "$SIMPLE_NAME" up
    ip link set "$SIMPLE_NAME" promisc on


done
