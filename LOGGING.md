# Container Logging Guide for bitw_xdp

This document outlines the logging strategies for the containerized AF_XDP packet forwarder.

## Current Logging Features

### 1. Structured Logging with Timestamps
- **Format**: `[2026-01-21T17:32:51.279Z] [INFO] message`
- **Timestamps**: ISO 8601 UTC format with milliseconds
- **Log Levels**: DEBUG, INFO, WARN, ERROR
- **Output**: All logs go to stderr for Docker capture

### 2. Log Level Usage
- **ERROR**: Critical failures (socket creation, thread affinity)
- **WARN**: Fallback scenarios (ZEROCOPY → COPY mode)
- **INFO**: Normal operations (socket binding, thread pinning, statistics)
- **DEBUG**: Verbose details (thread affinity verification, packet inspection)

## Container Logging Strategies

### Option 1: Docker Logs (Current/Recommended)
**How it works**: All stdout/stderr is captured by Docker daemon
```bash
# View real-time logs
sudo docker logs -f <container_name>

# View logs with timestamps
sudo docker logs -t <container_name>

# View last N lines
sudo docker logs --tail 100 <container_name>

# Filter by time
sudo docker logs --since "2026-01-21T17:30:00" <container_name>
```

**Pros:**
- No additional setup required
- Integrates with Docker ecosystem
- Logs persist until container is removed
- Easy to view and search

**Cons:**
- Logs are lost when container is removed
- Limited retention policies
- Single host only

### Option 2: Volume-Mounted Log Files
Add a log volume mount to your container:

```bash
# Create log directory on host
sudo mkdir -p /var/log/bitw_xdp

# Run with log volume
sudo docker run --privileged --network=host --rm \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /sys:/sys \
    -v /proc:/proc \
    -v /var/log/bitw_xdp:/app/logs \
    bitw_xdp:docker-only eth0 eth1 --cpu.forwarding 2 --cpu.return 3 2>&1 | tee /app/logs/bitw_xdp.log
```

**Pros:**
- Logs persist after container removal
- Can be rotated with logrotate
- Easy backup and archival

**Cons:**
- Requires host filesystem access
- Manual log rotation setup

### Option 3: Syslog Integration
For production environments, you can redirect to syslog:

```bash
# Install rsyslog in container (modify Dockerfile)
RUN apt-get update && apt-get install -y rsyslog

# Run with syslog driver
sudo docker run --log-driver=syslog --log-opt syslog-address=udp://localhost:514 \
    --privileged --network=host --rm \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /sys:/sys \
    -v /proc:/proc \
    bitw_xdp:docker-only eth0 eth1
```

**Pros:**
- Centralized logging
- Integrates with existing log infrastructure
- Remote logging capabilities
- Professional log management

**Cons:**
- More complex setup
- Requires syslog daemon configuration

### Option 4: Log Shipping to External Systems
For enterprise environments:

```bash
# Using Fluentd/Fluent Bit
sudo docker run --log-driver=fluentd --log-opt fluentd-address=localhost:24224 \
    --privileged --network=host --rm \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /sys:/sys \
    -v /proc:/proc \
    bitw_xdp:docker-only eth0 eth1

# Or using journald
sudo docker run --log-driver=journald \
    --privileged --network=host --rm \
    -v /sys/fs/bpf:/sys/fs/bpf \
    -v /sys:/sys \
    -v /proc:/proc \
    bitw_xdp:docker-only eth0 eth1
```

## Verbose Debug Logging

Enable detailed packet inspection:
```bash
sudo docker run --privileged --network=host --rm \
    -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \
    -e BUMP_VERBOSE=1 \
    bitw_xdp:docker-only eth0 eth1
```

This adds DEBUG level logs showing:
- EtherType of each forwarded packet
- Packet lengths
- VLAN tag information
- Malformed packet detection

## Log Analysis Examples

### View Container Startup Sequence
```bash
sudo docker logs <container> | grep -E "(INFO|ERROR)" | head -20
```

### Monitor Packet Forwarding
```bash
sudo docker logs -f <container> | grep "DEBUG.*RX"
```

### Check for Errors
```bash
sudo docker logs <container> | grep "ERROR"
```

### Performance Statistics
```bash
# View thread pinning and socket binding info
sudo docker logs <container> | grep -E "(pinned|bound|prefilled)"
```

## Best Practices

1. **Use Docker logs for development** - Simple and effective
2. **Use volume mounts for production** - Persistent logging
3. **Enable verbose mode only for debugging** - High performance impact
4. **Set up log rotation** - Prevent disk space issues
5. **Monitor ERROR logs** - Critical failure alerts
6. **Use structured logs for parsing** - JSON format for advanced analysis

## Log Rotation (Volume Mount Strategy)

Create `/etc/logrotate.d/bitw_xdp`:
```bash
/var/log/bitw_xdp/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

This provides a robust logging solution suitable for both development and production environments.