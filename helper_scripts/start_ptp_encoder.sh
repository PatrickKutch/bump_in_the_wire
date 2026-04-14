#!/bin/bash
# encoder_sync.sh

echo "Cleaning up existing PTP processes..."
sudo pkill ptp4l
sudo pkill phc2sys
sleep 2

# 1. Sync System Clock to eth0 (The Master Source)
# Using & at the end to background the process
sudo phc2sys -s eth0 -c CLOCK_REALTIME -w -m > /tmp/phc2sys_eth0.log 2>&1 &
echo "Syncing System Clock to eth0..."

# 2. Sync eth1 to the System Clock (Internal Bridge)
sudo phc2sys -s CLOCK_REALTIME -c eth1 -w -m > /tmp/phc2sys_eth1.log 2>&1 &
echo "Syncing eth1 to System Clock..."

# 3. Start PTP Master on eth1
sudo ptp4l -i eth1 -m -H -2  > /tmp/ptp4l_eth1.log 2>&1 &
echo "PTP Master started on eth1."

echo "Encoder synchronization is running in the background."
