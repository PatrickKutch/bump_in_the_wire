#!/bin/bash
# decoder_sync.sh

echo "Cleaning up existing PTP processes..."
sudo pkill ptp4l
sudo pkill phc2sys
sleep 2

# 1. Listen for PTP from Encoder on eth0
sudo ptp4l -i eth0 -m -H -s -2  > /tmp/ptp4l_eth0.log 2>&1 &
echo "PTP Slave started on eth0 (Listening to Encoder)..."

# 2. Sync System Clock to eth0
sudo phc2sys -s eth0 -c CLOCK_REALTIME -w -m > /tmp/phc2sys_eth0.log 2>&1 &
echo "Syncing System Clock to eth0..."

# 3. Sync eth1 to the System Clock
sudo phc2sys -s CLOCK_REALTIME -c eth1 -w -m > /tmp/phc2sys_eth1.log 2>&1 &
echo "Syncing eth1 to System Clock..."

echo "Decoder synchronization is running in the background."
