# Theory of Operations

This document describes the internal architecture and operation of the bitw_xdp packet processing system, focusing on the two main programs: `bitw_sflow` and `bitw_filter`.

## System Architecture Overview

The bitw_xdp system implements high-performance "bump-in-the-wire" packet processing using AF_XDP (eXpress Data Path) for kernel bypass networking. Both programs follow a similar architectural pattern:

- **Bidirectional packet forwarding** between two network interfaces (A↔B)
- **Asymmetric processing**: A→B direction performs specialized operations, B→A is simple forwarding
- **Multi-threaded architecture** with dedicated threads for forwarding and processing
- **Zero-copy packet handling** using shared memory regions (UMEM)
- **Thread-safe queues** for inter-thread communication using vectors and mutexes

## Common Infrastructure

### AF_XDP Foundation
Both programs use AF_XDP sockets for high-performance packet I/O:
- **UMEM (User Memory)**: Shared memory region for zero-copy packet buffers
- **Ring buffers**: Fill, RX, TX, and Completion rings for efficient packet transfer
- **Frame management**: Dynamic allocation/deallocation of memory frames
- **Fallback modes**: ZEROCOPY → COPY → SKB with automatic detection

### Threading Model
Each program implements a similar multi-threaded architecture:
1. **Forwarding threads** (2): One for A→B direction, one for B→A direction
2. **Processing threads** (1+): Specialized threads for packet analysis and modification
3. **CPU pinning**: Optional assignment of threads to specific CPU cores for performance

### Packet Flow Architecture
```
Interface A → [RX Ring] → [Processing Logic] → [TX Ring] → Interface B
Interface B → [RX Ring] → [Simple Forward] → [TX Ring] → Interface A
```

---

## bitw_sflow - S-Flow Sampling & Watermarking

### Program Overview
The `bitw_sflow` program implements network sampling with TCP packet watermarking for latency measurement. It performs transparent bidirectional packet forwarding while sampling specific packets in the A→B direction and creating timestamped watermarked copies.

### A→B Direction Processing Flow

#### 1. Packet Reception
- **AF_XDP RX**: Packets arrive from Interface A via AF_XDP RX ring
- **Batch processing**: Up to 64 packets processed per iteration for efficiency
- **Frame management**: Each packet occupies a frame in the shared UMEM region

#### 2. Sampling Decision Engine
```cpp
// Sampling logic in forward_worker_sflow()
if (should_sample_packet(layers.ethertype, cmd.sflow.sampling_rate)) {
    // Packet selected for sampling
    queue_for_sflow_processing(packet_data);
}
```

The sampling engine evaluates each packet against:
- **EtherType filtering**: Only configured protocols (IPv4: 0x800, IPv6: 0x86DD, etc.)
- **Sampling rate**: Statistical sampling (1 in N packets)
- **VLAN awareness**: Optional VLAN tag skipping
- **Packet validity**: Proper layer parsing and minimum size requirements

#### 3. Packet Forwarding
All packets (sampled and non-sampled) are forwarded normally:
- **Frame allocation**: Allocate output frame from Interface B's UMEM
- **Memory copy**: `memcpy()` packet data from input to output frame
- **TX submission**: Submit frame to AF_XDP TX ring for transmission
- **TX kick**: `sendto()` syscall to trigger transmission

#### 4. S-Flow Processing Thread
Sampled packets are queued using thread-safe vectors for processing:

```cpp
// Thread-safe queue implementation
class ThreadSafeQueue<SFlowInputPacket> {
    std::queue<SFlowInputPacket> queue_;
    std::mutex mutex_;
    std::condition_variable condition_;
};
```

**Processing steps:**
1. **Dequeue packet**: Remove packet from processing queue
2. **Protocol analysis**: Verify TCP packet structure
3. **Watermark creation**: Generate hash and timestamp payload
4. **Packet modification**: 
   - Change destination MAC to magic address (02:00:00:00:00:01)
   - Set TCP Reserved bits as watermark indicator
   - Replace payload with 16-byte watermark: `[hash:8][timestamp:8]`
5. **Transmission**: Send watermarked copy to Interface B

#### 5. Timestamping Mechanisms
Two timestamping modes are supported:
- **Hardware timestamping** (`--sample.hw_timestamp=true`): Uses IEEE 1588 PTP
- **Software timestamping** (default): Uses system clock via `clock_gettime()`

### B→A Direction Processing Flow
**Simple forwarding only** - no sampling or processing:
1. Receive packets from Interface B
2. Allocate frames in Interface A's UMEM  
3. Copy packet data directly
4. Submit to TX ring for transmission

### Thread Architecture
1. **Forwarding thread A→B**: Handles packet I/O + sampling decisions (CPU core 0 or configured)
2. **Forwarding thread B→A**: Simple forwarding (CPU core 1 or configured)  
3. **S-Flow processing thread**: Watermark creation and transmission (CPU core 0/1 or separate core)

---

## bitw_filter - Watermark Detection & Filtering

### Program Overview  
The `bitw_filter` program detects and removes watermarked packets while measuring network latency. It performs bidirectional packet forwarding with watermark detection and selective packet dropping in the A→B direction.

### A→B Direction Processing Flow

#### 1. Packet Reception
- **AF_XDP RX**: Packets arrive from Interface A via AF_XDP RX ring
- **Batch processing**: Up to 64 packets per iteration
- **Per-packet analysis**: Every packet examined for watermark signatures

#### 2. Magic MAC Filtering
First-stage filtering based on destination MAC address:
```cpp
// Only check packets with magic MAC address
bool mac_matches = std::memcmp(frame, watermark_dest_mac, 6) == 0;
if (mac_matches) {
    // Proceed with watermark detection
}
```
This optimizes performance by only analyzing relevant packets.

#### 3. Watermark Detection Engine
For packets matching the magic MAC:

**TCP Reserved Bits Check:**
```cpp
uint8_t tcp_flags_byte = layers.l4_header[12];
uint8_t reserved_bits = (tcp_flags_byte >> 4) & 0x0F;
bool has_watermark = (reserved_bits != 0) && (layers.l4_payload_len == 16);
```

**Payload Validation:**
- Extract 16-byte payload: `[hash:8][timestamp:8]`
- Convert from network byte order to host byte order
- Validate timestamp is within reasonable bounds

#### 4. Packet Decision Logic
Based on watermark detection results:
- **Watermarked packets**: Mark for dropping, queue for latency analysis
- **Normal packets**: Forward unchanged
- **Non-matching MAC**: Forward unchanged

#### 5. Latency Processing Thread
Watermarked packets are queued for detailed analysis:

```cpp
// Watermarked packet structure
struct WatermarkedPacket {
    std::vector<uint8_t> data;      // Full packet copy
    uint32_t length;                // Packet length
    PacketLayers layers;            // Parsed protocol layers
    int socket_fd;                  // Socket for timestamp extraction
};
```

**Processing steps:**
1. **Dequeue watermarked packet**: Remove from thread-safe queue
2. **Timestamp extraction**: Get current RX timestamp (hardware or software)
3. **Latency calculation**: `current_time - embedded_timestamp`
4. **Hash validation**: Verify packet integrity using embedded hash
5. **Logging**: Record latency measurements and statistics

#### 6. Selective Packet Forwarding
Only non-watermarked packets are transmitted:
- **Frame allocation**: Allocate output frames only for forwarded packets
- **Batch optimization**: Skip TX allocation for dropped packets  
- **Statistics tracking**: Count total, watermarked, and dropped packets

### B→A Direction Processing Flow
**Simple forwarding only** - no watermark detection:
1. Receive packets from Interface B
2. Forward all packets unchanged to Interface A
3. No processing queue or analysis

### Thread Architecture  
1. **Forwarding thread A→B**: Packet I/O + watermark detection (CPU core 0 or configured)
2. **Forwarding thread B→A**: Simple forwarding (CPU core 1 or configured)
3. **Watermark processing thread**: Latency analysis and logging (CPU core 0/1 or separate core)

---

## Inter-Thread Communication

### Thread-Safe Queue Implementation
Both programs use a custom thread-safe queue for communication between forwarding and processing threads:

```cpp
template<typename T>
class ThreadSafeQueue {
private:
    std::mutex mutex_;
    std::queue<T> queue_;
    std::condition_variable condition_;
    
public:
    void push(T item);                    // Thread-safe enqueue
    bool try_pop(T& item);               // Non-blocking dequeue
    bool wait_and_pop(T& item, int timeout_ms);  // Blocking dequeue with timeout
};
```

### Memory Management
- **Vector storage**: Packet data stored in `std::vector<uint8_t>` for safe copying
- **Bounded queues**: Maximum queue sizes prevent unbounded memory growth
- **Emergency recycling**: I226-optimized frame recycling for stuck TX completions

### Processing Flow Control
- **Backpressure handling**: Queue size monitoring and warnings
- **Timeout mechanisms**: Processing threads use timeouts to check shutdown signals
- **Statistics reporting**: Periodic logging of queue sizes and processing rates

---

## Performance Optimizations

### CPU Pinning Strategy
Both programs support flexible CPU assignment:
- **Single core**: Both forwarding directions share one CPU
- **Dual core forwarding**: A→B and B→A on separate CPUs  
- **Processing separation**: Specialized processing threads on dedicated CPUs

### Memory Optimizations
- **Zero-copy forwarding**: Direct memory mapping between kernel and userspace
- **Frame recycling**: Efficient reuse of memory frames
- **Batch processing**: Multiple packets processed per system call

### I226-Specific Optimizations
For Intel I226 consumer-grade NICs:
- **Copy-mode forcing**: Bypass zero-copy mode for stability
- **Enhanced frame management**: Optimized allocation patterns
- **Emergency recycling**: Handle delayed TX completion notifications

---

## Error Handling and Resilience

### Fallback Mechanisms
- **Socket binding**: ZEROCOPY → COPY → SKB automatic fallback
- **Timestamping**: Hardware → Software timestamp fallback
- **Frame allocation**: Emergency recycling when frames are exhausted

### Queue Management
- **Size limits**: Prevent memory exhaustion from processing backlogs
- **Drop policies**: Remove oldest entries when queues are full
- **Monitoring**: Log queue sizes and processing statistics

### Thread Coordination
- **Graceful shutdown**: Signal-based coordination for clean termination
- **Resource cleanup**: Proper AF_XDP socket and UMEM cleanup
- **Error propagation**: Thread errors reported to main process

---

## Conclusion

The bitw_xdp system demonstrates advanced AF_XDP programming techniques for high-performance packet processing. The asymmetric processing model (complex A→B, simple B→A) provides efficient resource utilization while maintaining full bidirectional connectivity. The multi-threaded architecture with thread-safe queues enables parallel processing of forwarding and analysis tasks without blocking critical packet forwarding operations.