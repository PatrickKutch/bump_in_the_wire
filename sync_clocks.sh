#!/bin/bash

echo "=== Clock Synchronization Workflow ==="

# Step 1: Start PTP4L to sync NIC hardware clocks
echo "Step 1: Starting PTP4L to synchronize NIC clocks..."
./start_ptp.sh

# Step 2: Wait for PTP convergence
echo "Step 2: Waiting for PTP convergence (60 seconds)..."
sleep 60

# Step 3: Check PTP status
echo "Step 3: Checking PTP synchronization status..."
tail -10 /var/log/ptp4l.log

# Step 4: Sync system clock to NIC clock
echo "Step 4: Syncing system clock to NIC hardware clock..."
HOSTNAME=$(hostname)

case "$HOSTNAME" in
    "npg-svr-32")
        echo "Syncing system clock to PF0 hardware clock (Master)"
        # Sync system clock to the master's hardware clock
        phc2sys -s PF0 -c CLOCK_REALTIME -w -m -R 8 > /var/log/phc2sys.log 2>&1 &
        PHC_PID=$!
        ;;
    "npg-svr-33")
        echo "Syncing system clock to PF0 hardware clock (Slave)"
        # Sync system clock to the slave's synchronized hardware clock
        phc2sys -s PF0 -c CLOCK_REALTIME -w -m -R 8 > /var/log/phc2sys.log 2>&1 &
        PHC_PID=$!
        ;;
    *)
        echo "Unknown hostname: $HOSTNAME"
        echo "Syncing system clock to PF0 hardware clock (Auto)"
        phc2sys -s PF0 -c CLOCK_REALTIME -w -m -R 8 > /var/log/phc2sys.log 2>&1 &
        PHC_PID=$!
        ;;
esac

# Step 5: Wait for system clock sync
echo "Step 5: Waiting for system clock synchronization (30 seconds)..."
sleep 30

# Step 6: Check system clock sync status
echo "Step 6: Checking system clock sync status..."
tail -5 /var/log/phc2sys.log

# Step 7: Stop PTP4L (no longer needed for runtime)
echo "Step 7: Stopping PTP4L (hardware clocks are now synchronized)..."
pkill ptp4l

# Step 8: Keep phc2sys running to maintain system clock sync
echo "Step 8: Keeping phc2sys running to maintain system clock sync..."
echo "phc2sys PID: $PHC_PID"

echo "=== Clock Synchronization Complete ==="
echo ""
echo "Hardware clocks: Synchronized via PTP (now stopped)"
echo "System clocks: Syncing to hardware clock via phc2sys (PID: $PHC_PID)"
echo ""
echo "You can now run your AF_XDP programs:"
echo "  ./bitw_sflow PF0 PF1 --sample.sampling=1000 --sample.ethertypes=0x800"
echo "  ./bitw_filter PF0 PF1 --watermark.ethertypes=0x800 --watermark.dest_mac=aa:bb:cc:dd:ee:ff"
echo ""
echo "Monitor system clock sync: tail -f /var/log/phc2sys.log"
echo "Stop system clock sync: kill $PHC_PID"