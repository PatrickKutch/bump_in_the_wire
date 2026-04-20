#include "bitw_common.h"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <chrono>

// Version and program information
static const char* PROGRAM_VERSION = "v26.04.13";
static const char* PROGRAM_NAME = "bitw_filter";
static const char* PROGRAM_AUTHOR = "Patrick Kutch";

// -----------------------------------------------------------------------------
// Thread-safe queue template
// -----------------------------------------------------------------------------
template<typename T>
class ThreadSafeQueue {
private:
    mutable std::mutex mutex_;
    std::queue<T> queue_;
    std::condition_variable condition_;

public:
    void push(T item) {
        std::lock_guard<std::mutex> lock(mutex_);
        // Prevent unbounded growth - drop oldest items if queue gets too large
        static constexpr size_t MAX_QUEUE_SIZE = 1000;
        while (queue_.size() >= MAX_QUEUE_SIZE) {
            queue_.pop(); // Remove oldest item
        }
        queue_.push(std::move(item));
        condition_.notify_one();
    }

    bool try_pop(T& item) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) {
            return false;
        }
        item = std::move(queue_.front());
        queue_.pop();
        return true;
    }

    bool wait_and_pop(T& item, int timeout_ms = -1) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (timeout_ms < 0) {
            condition_.wait(lock, [this] { return !queue_.empty(); });
        } else {
            if (!condition_.wait_for(lock, std::chrono::milliseconds(timeout_ms), 
                                   [this] { return !queue_.empty(); })) {
                return false; // timeout
            }
        }
        item = std::move(queue_.front());
        queue_.pop();
        return true;
    }

    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
};

// -----------------------------------------------------------------------------
// Watermarked packet structure for queue communication
// -----------------------------------------------------------------------------
struct WatermarkedPacket {
    std::vector<uint8_t> data;
    uint32_t length;
    PacketLayers layers;
    int socket_fd;
    
    WatermarkedPacket(const uint8_t* frame, uint32_t len, const PacketLayers& pkt_layers, int fd)
        : data(frame, frame + len), length(len), layers(pkt_layers), socket_fd(fd) {}
};

// -----------------------------------------------------------------------------
// Watermark detection and filtering functions
// -----------------------------------------------------------------------------

// Check if a TCP packet is watermarked by examining Reserved bits
// currently unused - was used in early testing but now we rely on magic MAC address filtering instead
static bool is_watermarked_tcp_packet(const PacketLayers& layers) {
    // Check TCP Reserved bits (upper 4 bits of byte 12 in TCP header)
    uint32_t reserved_byte_offset = 12; // Relative to TCP header start
    if (layers.l4_header_len < 13) return false; // Need at least 13 bytes for flags byte
    
    uint8_t tcp_flags_byte = layers.l4_header[reserved_byte_offset];
    uint8_t reserved_bits = (tcp_flags_byte >> 4) & 0x0F;
    
    // Must have non-zero Reserved bits AND exactly 16-byte payload (our watermark format)
    return (reserved_bits != 0) && (layers.l4_payload_len == 16);
}

// Check if a UDP packet is watermarked (future implementation)
static bool is_watermarked_udp_packet(const PacketLayers& /* layers */) {
    // TODO: Implement UDP watermark detection
    // UDP doesn't have Reserved bits like TCP, so we'd need a different approach
    // Possibilities:
    // - Magic bytes at start/end of payload
    // - Specific UDP port ranges
    // - Payload length patterns
    // - Checksum modifications
    return false;
}

// Main watermark detection dispatcher - calls appropriate protocol handler
// Since we now filter by magic MAC address, we only need to check protocol-specific watermarks
static bool is_watermarked_packet(const uint8_t* /* frame */, uint32_t /* len */, const PacketLayers& layers) {
    if (!layers.valid) {
        LOG(LogLevel::ERROR, "Invalid packet layers for watermark detection");
        return false;
    }
    
    switch (layers.l4_protocol) {
        case 6:  // TCP
            return is_watermarked_tcp_packet(layers);
        case 17: // UDP
            return is_watermarked_udp_packet(layers);
        // Add other protocols as needed:
        // case 1:  // ICMP
        // case 58: // ICMPv6
        default:
            return false; // Unknown/unsupported protocol
    }
}

// Process a detected watermarked packet
static void process_watermarked_packet(const char* tag, const PacketLayers& layers, uint32_t len, int sockfd, bool use_hw_timestamp) {
    // Debug: Show raw payload bytes
    // LOG(LogLevel::DEBUG, "Raw payload (%u bytes): %02X %02X %02X %02X %02X %02X %02X %02X | %02X %02X %02X %02X %02X %02X %02X %02X",
    //     layers.l4_payload_len,
    //     layers.l4_payload[0], layers.l4_payload[1], layers.l4_payload[2], layers.l4_payload[3],
    //     layers.l4_payload[4], layers.l4_payload[5], layers.l4_payload[6], layers.l4_payload[7],
    //     layers.l4_payload[8], layers.l4_payload[9], layers.l4_payload[10], layers.l4_payload[11],
    //     layers.l4_payload[12], layers.l4_payload[13], layers.l4_payload[14], layers.l4_payload[15]);
    
    // Extract watermark data
    uint64_t hash_be, timestamp_be;
    std::memcpy(&hash_be, layers.l4_payload, 8);
    std::memcpy(&timestamp_be, layers.l4_payload + 8, 8);
    
    uint64_t extracted_hash = be64toh(hash_be);
    uint64_t extracted_timestamp = be64toh(timestamp_be);
    
    // LOG(LogLevel::DEBUG, "Extracted BE values: hash_be=0x%016lX timestamp_be=0x%016lX", hash_be, timestamp_be);
    // LOG(LogLevel::DEBUG, "Converted LE values: hash=0x%016lX timestamp=%lu", extracted_hash, extracted_timestamp);
    
    // Extract Reserved bits value (not used in current watermarking approach, but can be useful for debugging)
    //uint8_t tcp_flags_byte = layers.l4_header[12];
    //uint8_t reserved_bits = (tcp_flags_byte >> 4) & 0x0F;
    
    // Get current timestamp for latency measurement based on configuration
    uint64_t rx_timestamp_ns = 0;
    bool has_timestamp = false;
    bool is_hw_timestamp = false;
    
    if (use_hw_timestamp) {
        // Try hardware timestamp first if enabled
        if (get_ptp_hw_timestamp(rx_timestamp_ns)) {
            has_timestamp = true;
            is_hw_timestamp = true;
        } else if (extract_hw_timestamp(sockfd, rx_timestamp_ns)) {
            has_timestamp = true;
            is_hw_timestamp = true;
        } else {
            // Fallback to system clock if hardware timestamp not available
            struct timespec ts;
            if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
                rx_timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
                has_timestamp = true;
                is_hw_timestamp = false;
            }
        }
    } else {
        // Use system clock directly when hardware timestamp disabled
        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
            rx_timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
            has_timestamp = true;
            is_hw_timestamp = false;
        }
    }
    
    // Debug: Show timestamp comparison
    // LOG(LogLevel::DEBUG, "Timestamp comparison: rx=%lu extracted=%lu has_ts=%s hw=%s", 
    //     rx_timestamp_ns, extracted_timestamp, has_timestamp ? "true" : "false", is_hw_timestamp ? "true" : "false");
    
    uint64_t latency_ns = 0;
    bool negative_latency = false;
    if (has_timestamp) {
        if (rx_timestamp_ns > extracted_timestamp) {
            latency_ns = rx_timestamp_ns - extracted_timestamp;
        } else {
            // If extracted timestamp is newer, this might indicate clock skew or old buffered packets
            latency_ns = extracted_timestamp - rx_timestamp_ns;
            negative_latency = true;
            LOG(LogLevel::DEBUG, "Negative latency detected - extracted timestamp is newer by %.3f ms", 
                static_cast<double>(latency_ns) / 1000000.0);
        }
    }
    double latency_ms = static_cast<double>(latency_ns) / 1000000.0;
    const char* ts_type = is_hw_timestamp ? "HW" : "SW";
    const char* latency_sign = negative_latency ? "-" : "";
    
    // If current log level is WARN or ERROR (INFO messages won't be shown), 
    // just print latency value for basic monitoring
    if (g_log_level >= LogLevel::WARN) {
        std::fprintf(stderr, "%.3f\n", latency_ms);  // Just print latency in ms, ignore sign
    } else {
        LOG(LogLevel::INFO, "[%s WATERMARK] Detected packet: hash=0x%016lX timestamp=%lu ns "
                            "latency=%s%.3f ms (%s) IPv%u len=%u",
            tag, extracted_hash, extracted_timestamp, latency_sign, latency_ms, ts_type,
            layers.ip_version, len);
    }
}

// -----------------------------------------------------------------------------
// Watermark processing thread
// -----------------------------------------------------------------------------
void watermark_processing_worker(const char* tag,
                               ThreadSafeQueue<WatermarkedPacket>& input_queue,
                               std::atomic<bool>& running,
                               int cpu_pin,
                               bool use_hw_timestamp) {
    if (cpu_pin >= 0) {
        if (pin_current_thread_to_cpu(cpu_pin) == 0) {
            LOG(LogLevel::INFO, "[%s WMARK-PROC] pinned to CPU %d", tag, cpu_pin);
        }
    }

    LOG(LogLevel::INFO, "[%s WMARK-PROC] Processing thread started", tag);

    while (running.load(std::memory_order_relaxed)) {
        WatermarkedPacket watermarked_packet{nullptr, 0, {}, -1}; // dummy initialization
        
        // Wait for watermarked packets to process (100ms timeout to check running flag)
        if (input_queue.wait_and_pop(watermarked_packet, 100)) {
            size_t queue_remaining = input_queue.size();
            // Process the watermarked packet
            process_watermarked_packet(tag, watermarked_packet.layers, 
                                     watermarked_packet.length, 
                                     watermarked_packet.socket_fd, use_hw_timestamp);
            
            // Log processing stats periodically
            // thread_local static uint32_t processed_count = 0;
            // processed_count++;
            // if ((processed_count % 1000) == 0) {
            //     LOG(LogLevel::INFO, "[%s WMARK-PROC] Processed %u watermarked packets, queue remaining: %zu", tag, processed_count, queue_remaining);
            // }
        }
    }

    LOG(LogLevel::INFO, "[%s WMARK-PROC] Processing thread shutting down", tag);
}

// -----------------------------------------------------------------------------
// Filtering: RX -> analyze -> optionally drop watermarked packets
// -----------------------------------------------------------------------------
void filter_step(const char* tag,
                 XskEndpoint& in_ep, UmemArea& in_umem,
                 XskEndpoint& out_ep, UmemArea& out_umem,
                 bool debug_print = false,
                 const uint8_t* watermark_dest_mac = nullptr,
                 ThreadSafeQueue<WatermarkedPacket>* watermark_queue = nullptr,
                 bool use_hw_timestamp = false)
{
    static constexpr uint32_t BATCH = 64;
    thread_local static uint32_t total_packets = 0;
    thread_local static uint32_t watermarked_packets = 0;
    thread_local static uint32_t dropped_packets = 0;

    // 1) Reap TX completions on output UMEM (recycle TX frames)
    {
        uint32_t c_idx = 0;
        unsigned int ncomp = xsk_ring_cons__peek(&out_umem.comp, BATCH, &c_idx);
        if (ncomp) {
            for (unsigned int i = 0; i < ncomp; ++i) {
                uint64_t done_addr = *xsk_ring_cons__comp_addr(&out_umem.comp, c_idx + i);
                free_frame(out_umem, done_addr);
            }
            xsk_ring_cons__release(&out_umem.comp, ncomp);
        }
    }

    // 2) Peek RX packets on input
    uint32_t rx_idx = 0;
    unsigned int rcvd = xsk_ring_cons__peek(&in_ep.rx, BATCH, &rx_idx);
    if (rcvd == 0) {
        return; // nothing to receive now
    }

    // Stash RX descriptors (addr,len)
    uint64_t rx_addrs[BATCH];
    uint32_t rx_lens[BATCH];
    bool forward_packet[BATCH];
    
    for (unsigned int i = 0; i < rcvd; ++i) {
        const struct xdp_desc* rxd = xsk_ring_cons__rx_desc(&in_ep.rx, rx_idx + i);
        rx_addrs[i] = rxd->addr;
        rx_lens[i]  = rxd->len;
        forward_packet[i] = true; // Default: forward all packets
    }

    // 3) Analyze packets for watermarks (only for A→B direction)
    if (std::strcmp(tag, "A→B") == 0) {
        for (unsigned int i = 0; i < rcvd; ++i) {
            const uint8_t* frame = umem_ptr(in_umem, rx_addrs[i]);
            total_packets++;
            
            // TODO: PTP packets (EtherType 0x88f7) should reach local kernel, not be processed by AF_XDP
            // This is a known limitation - AF_XDP intercepts all packets including PTP
            // Consider using separate interfaces for PTP and data traffic
            
            // Check destination MAC address for magic MAC - only process packets with matching MAC
            if (watermark_dest_mac != nullptr && rx_lens[i] >= 6) {
                bool mac_matches = std::memcmp(frame, watermark_dest_mac, 6) == 0;
                if (mac_matches) {
                    // Parse packet to check for watermark (magic MAC packets only)
                    PacketLayers layers = parse_packet_layers(frame, rx_lens[i]);
                    if (layers.valid && is_watermarked_packet(frame, rx_lens[i], layers)) {
                        watermarked_packets++;
                        dropped_packets++;
                        forward_packet[i] = false; // Drop watermarked packet
                        
                        // Queue watermarked packet for processing in separate thread
                        if (watermark_queue) {
                            WatermarkedPacket watermarked_pkt(frame, rx_lens[i], layers, in_ep.fd);
                            size_t queue_size_before = watermark_queue->size();
                            watermark_queue->push(std::move(watermarked_pkt));
                            // Log warning if queue is growing large (potential processing backlog)
                            if (queue_size_before > 500) {
                                LOG(LogLevel::WARN, "[%s] Watermark processing queue large: %zu packets (processing may be falling behind)", tag, queue_size_before);
                            }
                        } else {
                            // Fallback to direct processing if no queue provided
                            process_watermarked_packet(tag, layers, rx_lens[i], in_ep.fd, use_hw_timestamp);
                        }
                    }
                }
                // If MAC doesn't match magic MAC, packet is forwarded normally
            }
            // Note: If no magic MAC is specified, no watermark filtering is performed
            
            // Debug: log EtherType per packet
            if (debug_print) {
                uint16_t et = 0;
                if (parse_ethertype_vlan_aware(frame, rx_lens[i], et)) {
                    const char* action = forward_packet[i] ? "FORWARD" : "DROP";
                    LOG(LogLevel::DEBUG, "[%s RX] %s len=%u ethertype=0x%04x (%s)",
                        tag, action, rx_lens[i], et, ethertype_to_str(et));
                } else {
                    LOG(LogLevel::DEBUG, "[%s RX] FORWARD len=%u ethertype=? (frame too short/malformed)",
                        tag, rx_lens[i]);
                }
            }
        }
        
        // Periodic stats logging
        // if ((total_packets % 10000) == 0 && total_packets > 0) {
        //     double drop_rate = (static_cast<double>(dropped_packets) / total_packets) * 100.0;
        //     LOG(LogLevel::INFO, "[%s STATS] Total: %u, Watermarked: %u, Dropped: %u (%.2f%%)",
        //         tag, total_packets, watermarked_packets, dropped_packets, drop_rate);
        // }
    }

    // Count packets to forward
    unsigned int packets_to_forward = 0;
    for (unsigned int i = 0; i < rcvd; ++i) {
        if (forward_packet[i]) packets_to_forward++;
    }

    // 4) Reserve TX slots on output side (only for packets we're forwarding)
    uint32_t tx_idx = 0;
    unsigned int tx_space = packets_to_forward > 0 ? 
                           xsk_ring_prod__reserve(&out_ep.tx, packets_to_forward, &tx_idx) : 0;
    unsigned int to_tx = std::min(packets_to_forward, tx_space);
    
    if (packets_to_forward > 0 && to_tx == 0) {
        // No TX space available for forwarding - will drop all packets
        LOG(LogLevel::WARN, "[%s] No TX space available, dropping %u packets", tag, packets_to_forward);
    }

    // 5) Copy forwarded packets into output UMEM frames
    unsigned int tx_submitted = 0;
    for (unsigned int i = 0; i < rcvd && tx_submitted < to_tx; ++i) {
        if (!forward_packet[i]) continue; // Skip dropped packets
        
        uint64_t out_addr = 0;
        if (!alloc_frame(out_umem, out_addr)) {
            // Out of output frames
            LOG(LogLevel::WARN, "[%s] Out of TX frames, stopping at packet %u", tag, i);
            break;
        }

        const uint32_t len = rx_lens[i];
        uint8_t* src = umem_ptr(in_umem,  rx_addrs[i]);
        uint8_t* dst = umem_ptr(out_umem, out_addr);

        std::memcpy(dst, src, len);

        struct xdp_desc* txd = xsk_ring_prod__tx_desc(&out_ep.tx, tx_idx + tx_submitted);
        txd->addr = out_addr;
        txd->len  = len;

        tx_submitted++;
    }

    // 6) Submit TX and kick
    if (tx_submitted > 0) {
        xsk_ring_prod__submit(&out_ep.tx, tx_submitted);
        (void)sendto(out_ep.fd, nullptr, 0, MSG_DONTWAIT, nullptr, 0); // TX kick
    }

    // 7) Release RX descriptors we consumed
    xsk_ring_cons__release(&in_ep.rx, rcvd);

    // 8) Recycle RX frames back to input fill ring
    uint32_t f_idx = 0;
    unsigned int want_fill = rcvd;
    while (want_fill > 0) {
        unsigned int can = xsk_ring_prod__reserve(&in_umem.fill, want_fill, &f_idx);
        if (!can) break;
        for (unsigned int i = 0; i < can; ++i) {
            *xsk_ring_prod__fill_addr(&in_umem.fill, f_idx + i) = rx_addrs[i];
        }
        xsk_ring_prod__submit(&in_umem.fill, can);
        want_fill -= can;
    }
}

// -----------------------------------------------------------------------------
// Worker thread for filtering mode
// -----------------------------------------------------------------------------
void filter_worker(const char* tag,
                   XskEndpoint* in_ep, UmemArea* in_umem,
                   XskEndpoint* out_ep, UmemArea* out_umem,
                   std::atomic<bool>* running,
                   bool debug_print,
                   int cpu_pin,
                   const uint8_t* watermark_dest_mac,
                   ThreadSafeQueue<WatermarkedPacket>* watermark_queue = nullptr,
                   bool use_hw_timestamp = false)
{
    if (cpu_pin >= 0) {
        if (pin_current_thread_to_cpu(cpu_pin) == 0) {
            LOG(LogLevel::INFO, "[%s] pinned to CPU %d", tag, cpu_pin);
        }
    }

    struct pollfd pfd;
    pfd.fd = in_ep->fd;
    pfd.events = POLLIN;

    while (running->load(std::memory_order_relaxed)) {
        int pr = poll(&pfd, 1, 100 /*ms*/);
        if (pr < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        filter_step(tag, *in_ep, *in_umem, *out_ep, *out_umem, debug_print, watermark_dest_mac, watermark_queue, use_hw_timestamp);
    }
}

// -----------------------------------------------------------------------------
// Arg parsing
// -----------------------------------------------------------------------------
struct FilterCmd {
    const char* devA = nullptr;
    const char* devB = nullptr;
    int cpu_forwarding_cores[2] = {-1, -1}; // Support up to 2 cores for forwarding
    int cpu_return = -1;
    uint8_t dest_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}; // Default watermark MAC
    bool use_hw_timestamp = false; // false = use system clock, true = try hardware timestamp
    LogLevel log_level = LogLevel::WARN;  // Default to WARN
    bool verbose = false;                 // Default to not verbose
    bool i226_mode = false;               // I226-optimized AF_XDP settings
};

static void print_brief_overview() {
    std::cout << PROGRAM_NAME << " " << PROGRAM_VERSION << " - Watermark Packet Filter with AF_XDP\n";
    std::cout << "Author: " << PROGRAM_AUTHOR << "\n\n";
    std::cout << "PURPOSE:\n";
    std::cout << "  High-performance bidirectional packet filtering with TCP watermark detection.\n";
    std::cout << "  Detects and removes watermarked packets while forwarding normal traffic.\n\n";
    std::cout << "FEATURES:\n";
    std::cout << "  • Zero-copy AF_XDP packet forwarding (A↔B bidirectional)\n";
    std::cout << "  • TCP watermark detection (Reserved bits + hash+timestamp validation)\n";
    std::cout << "  • Selective packet dropping (watermarked packets only)\n";
    std::cout << "  • Hardware timestamp support (PTP-capable NICs)\n";
    std::cout << "  • CPU pinning for performance optimization\n";
    std::cout << "  • Intel I226 optimization mode\n\n";
    std::cout << "Use --help for detailed usage information.\n";
}

static void print_usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " <netdev_A> <netdev_B> [options]\n"
        << "\nWatermark Packet Filter with AF_XDP\n"
        << "Detects and drops TCP packets with watermark signatures based on magic MAC address filtering\n"
        << "\nCPU Pinning:\n"
        << "  --cpu.forwarding N[,M]  Pin A→B worker thread to CPU N (optionally second core M)\n"
        << "  --cpu.return M          Pin B→A worker thread to CPU M\n"
        << "\nWatermark Filtering:\n"
        << "  --watermark.dest_mac MAC  Magic destination MAC for watermark detection (e.g. 02:00:00:00:00:01)\n"
        << "                            Only packets with this destination MAC are analyzed for watermarks\n"
        << "                            (default: 02:00:00:00:00:01)\n"
        << "  --watermark.hw_timestamp B Use hardware timestamp (true/false, default: false)\n"
        << "\nHardware Compatibility:\n"
        << "  --i226-mode             Use Intel I226-optimized AF_XDP settings\n"
        << "\nLogging:\n"
        << "  --log-level LEVEL       Set log level: DEBUG, INFO, WARN, ERROR (default: WARN)\n"
        << "  --verbose               Enable per-packet debug prints (EtherType + action)\n"
        << "\nInformation:\n"
        << "  --version               Show program version\n"
        << "  --about                 Show program overview and features\n"
        << "\nExamples:\n"
        << "  " << prog << " eth0 eth1\n"
        << "  " << prog << " eth0 eth1 --cpu.forwarding 2 --cpu.return 3\n"
        << "  " << prog << " eth0 eth1 --watermark.dest_mac=02:00:00:00:00:01\n"
        << "  " << prog << " eth0 eth1 --watermark.dest_mac=02:00:00:00:00:01 --log-level INFO\n"
        << "\nWatermark Detection:\n"
        << "  - Uses magic destination MAC address to identify potential watermarked packets\n"
        << "  - Only packets matching the magic MAC are analyzed for watermark content\n"
        << "  - Expects 16-byte payload containing [hash:8][timestamp:8] in detected packets\n"
        << "  - Validates timestamp is within reasonable bounds\n"
        << "  - Drops watermarked packets from A→B, forwards B→A normally\n";
}

static bool parse_args(int argc, char** argv, FilterCmd& cmd) {
    if (argc < 3) return false;
    cmd.devA = argv[1];
    cmd.devB = argv[2];
    
    for (int i = 3; i < argc; ++i) {
        std::string arg(argv[i]);
        
        // Handle --option=value syntax
        size_t eq_pos = arg.find('=');
        std::string option = (eq_pos != std::string::npos) ? arg.substr(0, eq_pos) : arg;
        std::string value = (eq_pos != std::string::npos) ? arg.substr(eq_pos + 1) : "";
        
        if (option == "--cpu.forwarding") {
            std::string cpu_str = (eq_pos != std::string::npos) ? value : 
                                 (i + 1 < argc ? argv[++i] : "");
            if (cpu_str.empty()) {
                std::cerr << "Missing value for --cpu.forwarding\n";
                return false;
            }
            // Parse comma-separated CPU cores (up to 2)
            size_t comma_pos = cpu_str.find(',');
            if (comma_pos != std::string::npos) {
                cmd.cpu_forwarding_cores[0] = std::atoi(cpu_str.substr(0, comma_pos).c_str());
                cmd.cpu_forwarding_cores[1] = std::atoi(cpu_str.substr(comma_pos + 1).c_str());
            } else {
                cmd.cpu_forwarding_cores[0] = std::atoi(cpu_str.c_str());
            }
        } else if (option == "--cpu.return") {
            if (eq_pos != std::string::npos) {
                cmd.cpu_return = std::atoi(value.c_str());
            } else if (i + 1 < argc) {
                cmd.cpu_return = std::atoi(argv[++i]);
            } else {
                std::cerr << "Missing value for --cpu.return\n";
                return false;
            }
        } else if (option == "--watermark.dest_mac") {
            std::string mac_str = (eq_pos != std::string::npos) ? value : 
                                 (i + 1 < argc ? argv[++i] : "");
            if (mac_str.empty()) {
                std::cerr << "Missing value for --watermark.dest_mac\n";
                return false;
            }
            if (!parse_mac_address(mac_str.c_str(), cmd.dest_mac)) {
                std::cerr << "Failed to parse watermark destination MAC address\n";
                return false;
            }        } else if (option == "--watermark.hw_timestamp") {
            std::string hw_ts_str = (eq_pos != std::string::npos) ? value : 
                                   (i + 1 < argc ? argv[++i] : "");
            if (hw_ts_str.empty()) {
                std::cerr << "Missing value for --watermark.hw_timestamp\n";
                return false;
            }
            if (hw_ts_str == "true" || hw_ts_str == "1") {
                cmd.use_hw_timestamp = true;
            } else if (hw_ts_str == "false" || hw_ts_str == "0") {
                cmd.use_hw_timestamp = false;
            } else {
                std::cerr << "Invalid hw_timestamp value: " << hw_ts_str << " (use true/false)\n";
                return false;
            }        } else if (option == "--log-level") {
            std::string level_str = (eq_pos != std::string::npos) ? value : 
                                   (i + 1 < argc ? argv[++i] : "");
            if (level_str.empty()) {
                std::cerr << "Missing value for --log-level\n";
                return false;
            }
            if (level_str == "DEBUG") {
                cmd.log_level = LogLevel::DEBUG;
            } else if (level_str == "INFO") {
                cmd.log_level = LogLevel::INFO;
            } else if (level_str == "WARN") {
                cmd.log_level = LogLevel::WARN;
            } else if (level_str == "ERROR") {
                cmd.log_level = LogLevel::ERROR;
            } else {
                std::cerr << "Invalid log level: " << level_str << " (use DEBUG, INFO, WARN, ERROR)\n";
                return false;
            }
        } else if (option == "--verbose") {
            cmd.verbose = true;
        } else if (option == "--i226-mode") {
            cmd.i226_mode = true;
        } else if (option == "--about") {
            print_brief_overview();
            exit(0);
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            return false;
        }
    }
    
    return true;
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------
int main(int argc, char** argv) {
    // Handle special help arguments
    if (argc == 2) {
        std::string arg(argv[1]);
        if (arg == "/?" || arg == "/help" || arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        }
        if (arg == "/about" || arg == "--about") {
            print_brief_overview();
            return 0;
        }
        if (arg == "--version") {
            std::cout << PROGRAM_NAME << " " << PROGRAM_VERSION << std::endl;
            return 0;
        }
    }
    
    FilterCmd cmd {};
    if (!parse_args(argc, argv, cmd)) {
        print_usage(argv[0]);
        return 1;
    }

    const char* devA = cmd.devA;
    const char* devB = cmd.devB;

    // Apply log level and verbose settings
    set_log_level(cmd.log_level);
    set_verbose_mode(cmd.verbose);
    suppress_libbpf_messages();

    std::cout << "Watermark Packet Filter with AF_XDP\n";
    std::cout << "Device A: " << devA << "\n";
    std::cout << "Device B: " << devB << "\n";
    if (cmd.cpu_forwarding_cores[0] >= 0) {
        if (cmd.cpu_forwarding_cores[1] >= 0) {
            LOG(LogLevel::INFO, "Pin A→B thread to CPUs %d,%d", cmd.cpu_forwarding_cores[0], cmd.cpu_forwarding_cores[1]);
        } else {
            LOG(LogLevel::INFO, "Pin A→B thread to CPU %d", cmd.cpu_forwarding_cores[0]);
        }
    }
    if (cmd.cpu_return >= 0) LOG(LogLevel::INFO, "Pin B→A thread to CPU %d", cmd.cpu_return);

    // Trap Ctrl-C for graceful shutdown
    std::signal(SIGINT,  handle_signal);
    std::signal(SIGTERM, handle_signal);

    // Base socket config. Attempts are adjusted in create_xsk_with_fallback().
    struct xsk_socket_config base_cfg {};
    base_cfg.rx_size = 4096;
    base_cfg.tx_size = 4096;
    base_cfg.libbpf_flags = 0;

    // Parameters
    const uint32_t FRAME_COUNT = 4096; // tune as needed (reduced because frames are bigger)
    const uint32_t FRAME_SIZE  = 4096; // I226 requires better alignment - power of 2
    const uint32_t HEADROOM    = 256;  // I226 needs more headroom for metadata
    const uint32_t TX_RESERVE  = 1024; // reserve frames per UMEM for TX freelist

    // Verbose per-packet prints toggle
    const bool verbose = g_verbose_mode;

    // --- Setup UMEMs ---
    UmemArea umemA {};
    if (setup_umem(umemA, FRAME_COUNT, FRAME_SIZE, HEADROOM)) {
        std::cerr << "Failed to setup UMEM for " << devA << "\n";
        return 1;
    }
    UmemArea umemB {};
    if (setup_umem(umemB, FRAME_COUNT, FRAME_SIZE, HEADROOM)) {
        std::cerr << "Failed to setup UMEM for " << devB << "\n";
        xsk_umem__delete(umemA.umem); free(umemA.buffer);
        return 1;
    }

    // --- Create AF_XDP sockets with ZC->COPY->(SKB COPY) fallback ---
    XskEndpoint epA {}; // devA
    XskEndpoint epB {}; // devB

    // Check for I226 optimization mode (force copy-mode-only)
    bool force_copy_mode = cmd.i226_mode;

    bool A_zerocopy=false, A_skb=false;
    if (force_copy_mode) {
        LOG(LogLevel::INFO, "I226 mode enabled - using copy-mode-only binding for %s", devA);
        if (create_xsk_copy_mode_only(devA, epA, umemA, base_cfg, /*queue_id=*/0)) {
            xsk_umem__delete(umemB.umem); free(umemB.buffer);
            xsk_umem__delete(umemA.umem); free(umemA.buffer);
            return 1;
        }
    } else if (create_xsk_with_fallback(devA, epA, umemA, base_cfg, A_zerocopy, A_skb, /*queue_id=*/0, /*allow_skb_fallback=*/true)) {
        xsk_umem__delete(umemB.umem); free(umemB.buffer);
        xsk_umem__delete(umemA.umem); free(umemA.buffer);
        return 1;
    }

    bool B_zerocopy=false, B_skb=false;
    if (force_copy_mode) {
        LOG(LogLevel::INFO, "I226 mode enabled - using copy-mode-only binding for %s", devB);
        if (create_xsk_copy_mode_only(devB, epB, umemB, base_cfg, /*queue_id=*/0)) {
            xsk_socket__delete(epA.xsk);
            xsk_umem__delete(umemB.umem); free(umemB.buffer);
            xsk_umem__delete(umemA.umem); free(umemA.buffer);
            return 1;
        }
    } else if (create_xsk_with_fallback(devB, epB, umemB, base_cfg, B_zerocopy, B_skb, /*queue_id=*/0, /*allow_skb_fallback=*/true)) {
        xsk_socket__delete(epA.xsk);
        xsk_umem__delete(umemB.umem); free(umemB.buffer);
        xsk_umem__delete(umemA.umem); free(umemA.buffer);
        return 1;
    }

    // --- Reserve frames for TX ---
    init_free_frames_from_remaining(umemA);
    init_free_frames_from_remaining(umemB);

    // --- Prefill initial RX frames ---
    {
        uint32_t n = prefill_fill_ring_n(umemA, umemA.frame_count - TX_RESERVE);
        LOG(LogLevel::INFO, "Prefilled %u RX frames for %s", n, devA);
    }
    {
        uint32_t n = prefill_fill_ring_n(umemB, umemB.frame_count - TX_RESERVE);
        LOG(LogLevel::INFO, "Prefilled %u RX frames for %s", n, devB);
    }

    LOG(LogLevel::INFO, "Watermark detection enabled for A→B traffic (TCP Reserved bits + hash+timestamp payload)");
    LOG(LogLevel::INFO, "Hardware timestamp: %s", cmd.use_hw_timestamp ? "enabled" : "disabled (using system clock)");
    LOG(LogLevel::INFO, "Watermark magic MAC: %02X:%02X:%02X:%02X:%02X:%02X", 
        cmd.dest_mac[0], cmd.dest_mac[1], cmd.dest_mac[2],
        cmd.dest_mac[3], cmd.dest_mac[4], cmd.dest_mac[5]);
    LOG(LogLevel::INFO, "Only packets with magic MAC will be checked for watermarks");
    LOG(LogLevel::INFO, "Sockets created and rings mapped. Starting bidirectional filtering (multi-threaded)...");

    // --- Watermark processing state and queue (only needed for A→B direction) ---
    ThreadSafeQueue<WatermarkedPacket> watermark_queue;
    
    // Determine watermark processing CPU
    int watermark_processing_cpu = -1; // no pinning by default
    if (cmd.cpu_forwarding_cores[1] >= 0) {
        // Two cores specified: 2nd core for watermark processing
        watermark_processing_cpu = cmd.cpu_forwarding_cores[1];
        LOG(LogLevel::INFO, "Watermark processing will use CPU %d (separate from forwarding)", watermark_processing_cpu);
    } else if (cmd.cpu_forwarding_cores[0] >= 0) {
        // One core specified: same core as forwarding
        watermark_processing_cpu = cmd.cpu_forwarding_cores[0];
        LOG(LogLevel::INFO, "Watermark processing will use CPU %d (shared with forwarding)", watermark_processing_cpu);
    }
    
    // --- Launch watermark processing thread ---
    std::thread t_watermark_proc(
        watermark_processing_worker, "A→B",
        std::ref(watermark_queue),
        std::ref(g_running),
        watermark_processing_cpu,
        cmd.use_hw_timestamp);
    
    // --- Launch one worker thread per direction, with optional CPU pinning ---
    std::thread t_ab(
        filter_worker, "A→B",
        &epA, &umemA,
        &epB, &umemB,
        &g_running, verbose,
        cmd.cpu_forwarding_cores[0], cmd.dest_mac, &watermark_queue, cmd.use_hw_timestamp);

    std::thread t_ba(
        filter_worker, "B→A",
        &epB, &umemB,
        &epA, &umemA,
        &g_running, verbose,
        cmd.cpu_return, cmd.dest_mac, nullptr, cmd.use_hw_timestamp); // No watermark processing for B→A

    // Wait for Ctrl-C
    t_ab.join();
    t_ba.join();
    t_watermark_proc.join();

    // Cleanup
    xsk_socket__delete(epB.xsk);
    xsk_socket__delete(epA.xsk);
    xsk_umem__delete(umemB.umem); free(umemB.buffer);
    xsk_umem__delete(umemA.umem); free(umemA.buffer);
    return 0;
}