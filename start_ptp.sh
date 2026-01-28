
#!/bin/bash

# Kill any existing ptp4l processes
pkill ptp4l

# Check hostname to determine PTP role
HOSTNAME=$(hostname)

case "$HOSTNAME" in
    "npg-svr-32")
        echo "Starting PTP4L as MASTER on $HOSTNAME"
        nohup ptp4l -i PF0 -m -2 -f ./ptp4l.conf --priority1 128 > /var/log/ptp4l.log 2>&1 &
        ;;
    "npg-svr-33")
        echo "Starting PTP4L as SLAVE on $HOSTNAME"
        nohup ptp4l -i PF0 -s -m -2 -f ./ptp4l.conf --priority1 255 > /var/log/ptp4l.log 2>&1 &
        ;;
    *)
        echo "Unknown hostname: $HOSTNAME"
        echo "Defaulting to auto-negotiation mode"
        nohup ptp4l -i PF0 -m -2 -f ./ptp4l.conf > /var/log/ptp4l.log 2>&1 &
        ;;
esac

echo "PTP4L started. Monitor with: tail -f /var/log/ptp4l.log"
