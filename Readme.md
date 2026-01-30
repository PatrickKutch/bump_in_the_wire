
bitw_xdp

**bitw_xdp** is a high-performance, bidirectional AF_XDP packet forwarder written in C++. It supports zero-copy and copy-mode fallback, optional CPU pinning, and IEEE 1588 (PTP) RX timestamp extraction (if supported by the NIC and driver).

---

## 🚀 Features

- Bidirectional forwarding between two interfaces using AF_XDP
- Zero-copy (ZC) and copy-mode fallback with SKB fallback option
- Optional CPU pinning for each forwarding thread
- VLAN-aware EtherType parsing for debug
- Modular design for future sFlow-style packet inspection/modification

---

## 🛠️ Build Instructions

### Local Build
```bash
g++ -std=gnu++17 -Wall -O2 bitw_xdp.cpp -o bitw_xdp -lpthread -lxdp -lbpf
```

### Container Build

Build the containerized version using the provided helper script:
```bash
./build-docker-only.sh
```

Or build manually with Docker/Podman:
```bash
# Using Docker
docker build -t bitw_xdp:docker-only .

# Using Podman  
podman build -t bitw_xdp:docker-only .
```

The container includes both `bitw_sflow` and `bitw_filter` applications and uses Ubuntu 24.04 as the base image with libxdp packages.

### Ensure you have the following installed:

- libxdp
- libbpf
- Linux kernel headers
- A NIC and driver that support:
    - AF_XDP (XDP sockets)

## Interface Setup

Ports must be in promiscuous mode to ensure all packets are received:

```bash
sudo ip link set dev eth0 promisc on
sudo ip link set dev eth1 promisc on
```

You can verify the settings with:
```bash
sudo ip link show eth0
sudo ip link show eth1
```

## Usage

```bash
sudo ./bitw_xdp <netdev_A> <netdev_B> [--cpu.forwarding N[,M]] [--cpu.return M]
```

### Example
```bash
sudo ./bitw_xdp eth0 eth1 --cpu.forwarding 4 --cpu.return 8
```

This will:
- Forward packets from eth0 → eth1 on one thread pinned to CPU 4
- Forward packets from eth1 → eth0 on another thread pinned to CPU 8

### Environment Variable
BUMP_VERBOSE=1
- Enables per-packet debug output, including EtherType and length.

## 🐳 Containerized Usage

### Prerequisites for Container Execution
- **Root privileges required** - AF_XDP requires privileged access to network interfaces
- **Host networking** - Container must run with `--network=host` to access physical interfaces
- **Required volume mounts**:
  - `/sys/fs/bpf:/sys/fs/bpf` - BPF filesystem access for XDP programs
  - `/sys:/sys` - System information access
  - `/proc:/proc` - Process information access

### Using the Helper Script (Recommended)

The `run-container.sh` script simplifies container execution:

```bash
# S-Flow sampling (default mode)
sudo ./run-container.sh PF0 PF1
sudo ./run-container.sh --mode sflow PF0 PF1 --sample.sampling=1000 --sample.ethertypes=0x800

# Watermark filtering
sudo ./run-container.sh --mode filter eth0 eth1 --cpu.forwarding 4 --cpu.return 8 --watermark.ethertypes=0x800,0x86DD

# With verbose debugging
sudo BUMP_VERBOSE=1 ./run-container.sh eth0 eth1
```

### Direct Docker Commands

**S-Flow Sampling (bitw_sflow):**
```bash
# Basic S-Flow forwarding
sudo docker run --privileged --network=host --rm \
    -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \
    bitw_xdp:docker-only eth0 eth1

# With sampling configuration
sudo docker run --privileged --network=host --rm \
    -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \
    bitw_xdp:docker-only PF0 PF1 --sample.sampling=1000 --sample.ethertypes=0x800,0x86DD --sample.skip_vlan=true

# With CPU pinning
sudo docker run --privileged --network=host --rm \
    -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \
    bitw_xdp:docker-only eth0 eth1 --cpu-a 4 --cpu-b 8
```

**Watermark Filtering (bitw_filter):**
```bash
sudo docker run --privileged --network=host --rm \
    -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \
    -e BITW_MODE=filter \
    bitw_xdp:docker-only eth0 eth1 --cpu.forwarding 4 --cpu.return 8 --watermark.ethertypes=0x800,0x86DD
```

### Direct Podman Commands

Podman commands are identical to Docker, just replace `docker` with `podman`:

```bash
# S-Flow sampling
sudo podman run --privileged --network=host --rm \
    -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \
    bitw_xdp:docker-only PF0 PF1 --sample.sampling=1000 --sample.ethertypes=0x800

# Watermark filtering
sudo podman run --privileged --network=host --rm \
    -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \
    -e BITW_MODE=filter \
    bitw_xdp:docker-only eth0 eth1 --watermark.ethertypes=0x800,0x86DD
```

### Container Environment Variables

- `BITW_MODE=sflow` (default) - Run S-Flow sampling application
- `BITW_MODE=filter` - Run watermark filtering application  
- `BUMP_VERBOSE=1` - Enable verbose packet debugging

### Container Logs

View container logs in real-time:
```bash
# If running with --rm, logs appear directly in terminal
# For detached containers:
sudo docker logs -f <container_name>
sudo podman logs -f <container_name>
```



## Future Enhancements
- Add sFlow-style hook to inspect or modify packets using RX timestamps
- Export statistics (e.g., packet counts, latency)
- Add CLI options for timestamp logging or filtering