
# bitw_xdp

**bitw_xdp** is a high-performance AF_XDP packet forwarding system designed for network latency measurement, flow analysis, and traffic monitoring. This project was developed as an exploration into AF_XDP programming techniques and hardware timestamping capabilities. The system consists of two main programs that work together to provide "bump-in-the-wire" packet processing with minimal impact on network flows.

## ⚠️ PTP Compatibility Notice

**Important:** The current implementation does not support PTP (Precision Time Protocol) traffic coexistence. When these programs are active on an interface, PTP packets (EtherType 0x88f7) will be intercepted by AF_XDP and will not reach the kernel's PTP subsystem, potentially disrupting time synchronization.

**Possible workarounds (currently out of scope):**
- Create custom XDP filters to redirect PTP traffic to the kernel
- Use `ethtool` or `ip link` commands to route PTP traffic to dedicated RX queues not used by these programs
- Run PTP services on separate network interfaces not used by bitw_xdp programs

For deployments requiring PTP synchronization, consider using separate interfaces for data forwarding and time synchronization.

## 🏗️ System Overview

The bitw_xdp system provides two main programs and a testing utility:

- **`bitw_sflow`** - S-Flow sampling with TCP watermarking for packet timestamping
- **`bitw_filter`** - Watermark detection and latency measurement
- **`afx_tx`** - Standalone AF_XDP transmission testing tool

These programs use AF_XDP (eXpress Data Path) for high-performance, zero-copy packet processing at the kernel bypass level.

## 📊 Programs

### bitw_sflow - S-Flow Sampling & Watermarking

**Purpose:** Performs transparent packet forwarding with optional sampling and watermarking for network analysis.

**Key Features:**
- Bidirectional packet forwarding between two interfaces
- S-Flow-style packet sampling (configurable rate: 1 in N packets)
- TCP watermarking: Creates timestamped copies of sampled packets
- EtherType filtering (IPv4, IPv6, etc.)
- Hardware timestamping support (IEEE 1588 PTP)
- Zero-copy AF_XDP with fallback modes

**Usage:**
```bash
sudo ./bitw_sflow <interface_A> <interface_B> [options]
```

**Common Options:**
- `--sample.sampling N` - Sample 1 out of N packets (0=disabled)
- `--sample.ethertypes LIST` - Comma-separated EtherTypes (e.g., 0x800,0x86DD)
- `--sample.dest_mac MAC` - Magic MAC for watermarked packets (default: 02:00:00:00:00:01)
- `--sample.jitter Min,Max` - Apply random timestamp jitter (Min-Max nanoseconds) to watermarked packets
- `--cpu.forwarding N[,M]` - Pin forwarding thread to CPU N (or N,M for timestamping performance)
- `--cpu.return M` - Pin return thread to CPU M
- `--i226-mode` - Intel I226 optimization mode
- `--verbose` - Enable per-packet debug output

### bitw_filter - Watermark Detection & Filtering

**Purpose:** Detects watermarked packets, measures network latency, and provides selective filtering.

**Key Features:**
- Transparent packet forwarding with watermark detection
- Latency measurement between encoder and decoder points
- Selective packet filtering (removes watermarked packets)
- Hash validation for packet integrity checking
- Multi-threaded processing pipeline

**Usage:**
```bash
sudo ./bitw_filter <interface_A> <interface_B> [options]
```

**Common Options:**
- `--watermark.dest_mac MAC` - Magic MAC address to detect
- `--watermark.hw_timestamp BOOL` - Use hardware timestamping
- `--cpu.forwarding N[,M]` - Pin forwarding thread to CPU N (or N,M for filtering performance)
- `--cpu.return M` - Pin return thread to CPU M
- `--i226-mode` - Intel I226 optimization mode
- `--verbose` - Enable detailed packet analysis

### afx_tx - AF_XDP Transmission Test Tool

**Purpose:** Standalone program for testing AF_XDP transmission capabilities, particularly useful for driver debugging.

**Key Features:**
- Periodic packet transmission with configurable intervals
- Intel I226 compatibility workarounds
- TX completion monitoring and debugging
- Frame allocation tracking and emergency recycling
- IPv4/UDP packet generation with proper checksums

**Usage:**
```bash
sudo ./afx_tx <interface> <dest_mac> <interval_ms> [options]
```

**Common Options:**
- `--i226-mode` - Force I226-optimized settings
- `--verbose` - Detailed per-packet logging
- `--duration N` - Run for N seconds (0=forever)

## 🔬 Test Setup Topology

The system is designed for the following 4-system test configuration:

```
[ Client ] .10         [ Encoder ]            [ Decoder ]            [ Server ] .40
    │                      │                       │                      │
    │                      │                       │                      │
[eth1] <-----------> [eth0] [eth1] <-------> [eth0] [eth1] <---------> [eth0]

                     (Timestamping)          (Latency Calc)
```

### System Roles

**Client (100.100.100.10/24)**
- Role: Traffic generator (ping, netperf, etc.)
- Connection: eth1 → Encoder[eth0] 
- Purpose: Sends traffic to Server with no knowledge of intermediate systems

**Encoder** 
- Role: Bump-in-the-wire packet sampling and watermarking
- Program: `bitw_sflow`
- Connections: 
  - eth0 ← Client[eth1] (ingress)
  - eth1 → Decoder[eth0] (egress)
- Purpose: Samples packets, creates timestamped watermarked copies

**Decoder**
- Role: Bump-in-the-wire watermark detection and latency measurement  
- Program: `bitw_filter`
- Connections:
  - eth0 ← Encoder[eth1] (ingress)
  - eth1 → Server[eth0] (egress) 
- Purpose: Detects watermarked packets, measures latency, removes watermarks

**Server (100.100.100.40/24)**
- Role: Traffic responder and destination
- Connection: eth0 ← Decoder[eth1]
- Purpose: Receives and responds to traffic from Client

### Traffic Flow

1. **Normal Traffic:** Client → Encoder → Decoder → Server
2. **Sampled Packets:** Encoder creates watermarked copies with timestamps
3. **Latency Measurement:** Decoder measures time between encoding and detection
4. **Transparent Operation:** End-to-end connectivity preserved (Client ↔ Server)

## 🛠️ Build Instructions

### Prerequisites

- Linux kernel with AF_XDP support (4.18+)
- libxdp and libbpf development libraries
- GCC/G++ with C++17 support
- Root privileges (for AF_XDP socket operations)

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install build-essential libxdp-dev libbpf-dev linux-headers-$(uname -r)
```

### Local Build

```bash
# Build all programs
make clean && make

# Build individual programs
make bitw_sflow
make bitw_filter  
make afx_tx
```

### Container Build

```bash
# Using the helper script (recommended)
./build-docker-only.sh

# Manual Docker build
docker build -t bitw_xdp:docker-only .

# Manual Podman build
podman build -t bitw_xdp:docker-only .
```

### Container Packaging and Transfer

Once you've built the container, you can package it for transfer to target systems:

**Export Container Image:**
```bash
# Using Docker
docker save bitw_xdp:docker-only -o bitw_xdp-container.tar

# Using Podman  
podman save bitw_xdp:docker-only -o bitw_xdp-container.tar

# Optional: Compress for faster transfer
gzip bitw_xdp-container.tar
```

**Transfer to Target System:**
```bash
# Transfer compressed container
scp bitw_xdp-container.tar.gz user@target-system:/tmp/

# Or transfer uncompressed
scp bitw_xdp-container.tar user@target-system:/tmp/
```

**Load Container on Target System:**
```bash
# On the target system - decompress if needed
gunzip /tmp/bitw_xdp-container.tar.gz

# Load container image
docker load -i /tmp/bitw_xdp-container.tar
# Or for Podman:
podman load -i /tmp/bitw_xdp-container.tar

# Verify container is loaded
docker images | grep bitw_xdp
# Or for Podman:
podman images | grep bitw_xdp

# Clean up transfer file
rm /tmp/bitw_xdp-container.tar
```

**Alternative: Direct Transfer with Compression:**
```bash
# One-liner: build, save, compress, and transfer
docker save bitw_xdp:docker-only | gzip | ssh user@target-system 'gunzip | docker load'

# Or for Podman
podman save bitw_xdp:docker-only | gzip | ssh user@target-system 'gunzip | podman load'
```

## 🚀 Running the Programs

### Prerequisites Setup

**Interface Configuration:**
```bash
# Enable promiscuous mode (required for AF_XDP ports only - not Client/Server systems)
sudo ip link set dev eth0 promisc on
sudo ip link set dev eth1 promisc on

# Configure single RX queue for AF_XDP (required for optimal performance)
sudo ethtool -X eth0 equal 1
sudo ethtool -X eth1 equal 1

# Verify promiscuous mode settings
ip link show eth0 | grep PROMISC
ip link show eth1 | grep PROMISC
```

### Local Execution

**S-Flow Sampling:**
```bash
# Basic forwarding with sampling
sudo ./bitw_sflow eth0 eth1 --sample.sampling=10000 --sample.ethertypes=0x800

# With CPU pinning and verbose output
sudo ./bitw_sflow eth0 eth1 --sample.sampling=10000 --sample.ethertypes=0x800,0x86DD \
    --cpu.forwarding 4,5 --cpu.return 8 --verbose

# Skip VLAN tags and use hardware timestamping
sudo ./bitw_sflow eth0 eth1 --sample.sampling=10000 --sample.ethertypes=0x800 \
    --sample.skip_vlan=true --sample.hw_timestamp=true

# With timestamp jitter for latency distribution analysis
sudo ./bitw_sflow eth0 eth1 --sample.sampling=10000 --sample.ethertypes=0x800 \
    --sample.jitter=500000,1500000 --sample.hw_timestamp=true
```

**Watermark Filtering:**
```bash
# Basic watermark detection and filtering
sudo ./bitw_filter eth0 eth1

# With custom magic MAC and CPU pinning
sudo ./bitw_filter eth0 eth1 --watermark.dest_mac=02:00:00:00:00:01 \
    --cpu.forwarding 4,5 --cpu.return 8

# With hardware timestamping for precise latency measurement
sudo ./bitw_filter eth0 eth1 --watermark.hw_timestamp=true --cpu.forwarding 4,5
```

**Transmission Testing:**
```bash
# Basic AF_XDP TX test
sudo ./afx_tx eth0 aa:bb:cc:dd:ee:ff 1000

# Intel I226 optimized mode with verbose output
sudo ./afx_tx eth0 aa:bb:cc:dd:ee:ff 500 --i226-mode --verbose --duration 30
```

## 🐳 Container Usage

### Using the Helper Script (Recommended)

The `run-container.sh` script provides the easiest way to run containerized versions:

**S-Flow Sampling:**
```bash
# Basic S-Flow forwarding
sudo ./run-container.sh eth0 eth1

# With sampling configuration
sudo ./run-container.sh --mode sflow eth0 eth1 --sample.sampling=10000 --sample.ethertypes=0x800

# With verbose debugging
sudo ./run-container.sh eth0 eth1 --verbose
```

**Watermark Filtering:**
```bash
# Basic filtering
sudo ./run-container.sh --mode filter eth0 eth1

# With CPU pinning
sudo ./run-container.sh --mode filter eth0 eth1 --cpu.forwarding 4,5 --cpu.return 8
```

**Transmission Testing:**
```bash
# AF_XDP TX test
sudo ./run-container.sh --mode afx_tx eth0 aa:bb:cc:dd:ee:ff 1000

# With I226 optimizations
sudo ./run-container.sh --mode afx_tx eth0 aa:bb:cc:dd:ee:ff 1000 --i226-mode --verbose
```

### Direct Container Commands

**Docker:**
```bash
# S-Flow sampling
sudo docker run --privileged --network=host --rm \
    -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \
    bitw_xdp:docker-only eth0 eth1 --sample.sampling=1000

# Watermark filtering
sudo docker run --privileged --network=host --rm \
    -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \
    -e BITW_MODE=filter \
    bitw_xdp:docker-only eth0 eth1

# Transmission testing
sudo docker run --privileged --network=host --rm \
    -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \
    -e BITW_MODE=afx_tx \
    bitw_xdp:docker-only eth0 aa:bb:cc:dd:ee:ff 1000 --i226-mode
```

**Podman:**
```bash
# Replace 'docker' with 'podman' in above commands
sudo podman run --privileged --network=host --rm \
    -v /sys/fs/bpf:/sys/fs/bpf -v /sys:/sys -v /proc:/proc \
    bitw_xdp:docker-only eth0 eth1 --sample.sampling=1000
```

### Container Environment Variables

- `BITW_MODE=sflow` (default) - Run S-Flow sampling application
- `BITW_MODE=filter` - Run watermark filtering application  
- `BITW_MODE=afx_tx` - Run AF_XDP transmission test

### Container Logs

```bash
# Real-time logging (for containers run with --rm)
# Logs appear directly in terminal

# For detached containers
sudo docker logs -f <container_name>
sudo podman logs -f <container_name>
```

### Container Privileges and Mounts

**Required for AF_XDP operation:**
- `--privileged` - Full device access for network interface binding
- `--network=host` - Direct access to host network interfaces
- `-v /sys/fs/bpf:/sys/fs/bpf` - BPF filesystem for XDP programs
- `-v /sys:/sys` - System information access
- `-v /proc:/proc` - Process information access

## ⚙️ Advanced Configuration

### Intel I226 Compatibility

This system was originally developed and optimized for Intel E810 enterprise-grade NICs, which provide full AF_XDP feature support including zero-copy operation and hardware timestamping. The Intel I226 is a consumer-grade device with different capabilities, so the code includes specific provisions to optimize performance on I226 hardware:

```bash
# Use I226-optimized settings (forces copy-mode operation for stability)
sudo ./bitw_sflow eth0 eth1 --i226-mode

# Test transmission capabilities on I226 hardware
sudo ./afx_tx eth0 aa:bb:cc:dd:ee:ff 1000 --i226-mode --verbose
```

### Performance Tuning

**CPU Pinning:**
```bash
# Pin forwarding threads to specific CPUs (2 cores for better timestamping performance)
sudo ./bitw_sflow eth0 eth1 --cpu.forwarding 4,5 --cpu.return 8

# Pin forwarding threads for filtering performance (bitw_filter with 2 cores)
sudo ./bitw_filter eth0 eth1 --cpu.forwarding 4,5 --cpu.return 8

# Single CPU per direction (acceptable performance)
sudo ./bitw_sflow eth0 eth1 --cpu.forwarding 4 --cpu.return 6
```

### Debug and Monitoring

**Environment Variables:**
```bash
# Enable verbose packet debugging via command-line flag
sudo ./bitw_sflow eth0 eth1 --verbose
sudo ./bitw_filter eth0 eth1 --verbose
sudo ./afx_tx eth0 aa:bb:cc:dd:ee:ff 1000 --verbose
```

**Log Levels:**
```bash
# Set log level via command line
sudo ./bitw_sflow eth0 eth1 --log-level DEBUG

# Available levels: DEBUG, INFO, WARN, ERROR
```

**Network Statistics:**
```bash
# Monitor interface statistics
watch 'ethtool -S eth0 | grep -E "(rx_packets|tx_packets)"'

# Check AF_XDP socket stats
ss -xdp

# Monitor packet drops
cat /proc/net/dev | grep -E "(eth0|eth1)"
```

## 🔍 Troubleshooting

### Common Issues

**Permission Denied:**
```bash
# Ensure root privileges
sudo id
# Expected: uid=0(root) gid=0(root) groups=0(root)

# Check interface promiscuous mode  
ip link show eth0 | grep PROMISC
```

**Zero-Copy Bind Failures:**
```bash
# Expected behavior - program falls back to copy mode
[2026-04-13T10:30:15.123Z] [WARN] [eth0] ZC bind failed, trying copy mode
[2026-04-13T10:30:15.124Z] [INFO] [eth0] bound: DRV + COPY
```

**No Packet Forwarding:**
```bash
# Verify interface names exist
ip link show | grep -E "(eth0|eth1)"

# Check for XDP program conflicts
ip link show eth0 | grep xdp
ip link show eth1 | grep xdp

# Remove existing XDP programs if needed
sudo ip link set dev eth0 xdp off
sudo ip link set dev eth1 xdp off
```

**Intel I226 Optimizations:**
```bash
# Use I226-optimized mode
sudo ./bitw_sflow eth0 eth1 --i226-mode

# Test transmission separately
sudo ./afx_tx eth0 aa:bb:cc:dd:ee:ff 1000 --i226-mode --verbose

# Monitor TX statistics
watch 'ethtool -S eth1 | grep tx_packets'
```

### Container-Specific Issues

**BPF Mount Issues:**
```bash
# Ensure BPF filesystem is available
mount | grep bpf
# If missing, mount it:
sudo mkdir -p /sys/fs/bpf
sudo mount -t bpf bpf /sys/fs/bpf
```

**Container Runtime Selection:**
```bash
# Check available runtimes
which docker podman

# Force specific runtime
CONTAINER_RUNTIME=docker ./run-container.sh eth0 eth1
CONTAINER_RUNTIME=podman ./run-container.sh eth0 eth1
```

## 📈 Performance Characteristics

### Typical Performance

- **Forwarding Rate:** Up to 10+ Gbps per direction (depending on hardware)
- **Latency Impact:** < 10 microseconds additional latency
- **CPU Usage:** 10-50% per core (depending on packet rate and processing)
- **Memory Usage:** ~50-100MB per program (excluding kernel buffers)

### Scaling Guidelines

- **Small Deployments:** Run all programs on single multi-core system
- **High Performance:** Use separate systems for encode/decode functions
- **CPU Pinning:** Isolate forwarding threads from system interrupts
- **NUMA Awareness:** Pin to CPUs local to NIC interrupts

## 📚 Technical Documentation

### Packet Processing Pipeline

1. **AF_XDP RX:** Kernel delivers packets to userspace via shared memory
2. **Protocol Parsing:** Extract EtherType, VLAN tags, IP headers
3. **Sampling Decision:** Apply sampling rate and EtherType filtering
4. **Watermark Processing:** Create timestamped copies for sampled packets
5. **AF_XDP TX:** Transmit packets via kernel bypass

### Watermarking Protocol

**Format:** 16-byte payload structure
```c
struct WatermarkPayload {
    uint64_t hash;      // FNV-1a hash of IP payload
    uint64_t timestamp; // Nanosecond timestamp
};
```

**Detection:** Magic MAC address + TCP Reserved bits + payload validation

### Hardware Requirements

**Minimum:**
- Linux kernel 4.18+ with AF_XDP support
- Network interface with AF_XDP driver support
- 4GB+ RAM, multi-core CPU

**Recommended:**
- Intel E810 or compatible high-performance NIC
- Dedicated CPU cores for packet processing
- IEEE 1588 PTP support for hardware timestamping
- IOMMU/VT-d support for optimal zero-copy performance

## 🤝 Contributing

This project follows standard C++ development practices:

- **Code Style:** Follow existing formatting and naming conventions
- **Testing:** Test changes on both Intel E810 and I226 hardware
- **Documentation:** Update README and inline comments for new features
- **Compatibility:** Maintain backward compatibility where possible

## 📄 License

See project license file for terms and conditions.

---

*For additional information, see the inline documentation in source files and the provided configuration scripts.*