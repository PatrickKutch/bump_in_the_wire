
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

```bash
g++ -std=gnu++17 -Wall -O2 bitw_xdp.cpp -o bitw_xdp -lpthread -lxdp -lbpf
```

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
sudo ./bitw_xdp <netdev_A> <netdev_B> [--cpu-a N] [--cpu-b M]
```

### Example
```bash
sudo ./bitw_xdp eth0 eth1 --cpu-a 4 --cpu-b 8
```

This will:
- Forward packets from eth0 → eth1 on one thread pinned to CPU 4
- Forward packets from eth1 → eth0 on another thread pinned to CPU 8

### Environment Variable
BUMP_VERBOSE=1
- Enables per-packet debug output, including EtherType and length.



## Future Enhancements
- Add sFlow-style hook to inspect or modify packets using RX timestamps
- Export statistics (e.g., packet counts, latency)
- Add CLI options for timestamp logging or filtering