#include "bitw_common.h"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <chrono>

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
// S-Flow packet structures for queue communication
// -----------------------------------------------------------------------------
struct SFlowInputPacket {
    std::vector<uint8_t> data;
    uint32_t length;
    uint16_t ethertype;
    uint64_t timestamp_ns;
    bool has_timestamp;
    bool is_hw_timestamp;
    
    SFlowInputPacket(const uint8_t* frame, uint32_t len, uint16_t et,
                     uint64_t ts_ns = 0, bool has_ts = false, bool is_hw_ts = false)
        : data(frame, frame + len), length(len), ethertype(et),
          timestamp_ns(ts_ns), has_timestamp(has_ts), is_hw_timestamp(is_hw_ts) {}
};

// -----------------------------------------------------------------------------
// S-Flow specific functions
// -----------------------------------------------------------------------------

// Calculate hash of IP payload (TCP/UDP/etc.) excluding checksums
static inline uint64_t calculate_packet_hash(const uint8_t* data, uint32_t len) {
    // Parse packet to get IP payload
    PacketLayers layers = parse_packet_layers(data, len);
    if (!layers.valid || layers.l4_payload_len == 0) {
        // Fallback to full packet hash if parsing fails
        std::hash<std::string> hasher;
        std::string packet_str(reinterpret_cast<const char*>(data), len);
        return static_cast<uint64_t>(hasher(packet_str));
    }
    
    // For TCP/UDP, we want to hash the L4 header + payload but exclude checksums
    std::vector<uint8_t> hash_data;
    
    if (layers.l4_protocol == 6) { // TCP
        // TCP header is at layers.l4_header, checksum is at bytes 16-17
        if (layers.l4_header_len >= 18) {
            // Copy TCP header excluding checksum (bytes 16-17)
            hash_data.insert(hash_data.end(), layers.l4_header, layers.l4_header + 16);
            if (layers.l4_header_len > 18) {
                hash_data.insert(hash_data.end(), layers.l4_header + 18, layers.l4_header + layers.l4_header_len);
            }
        }
        // Add TCP payload
        if (layers.l4_payload_len > 0) {
            hash_data.insert(hash_data.end(), layers.l4_payload, layers.l4_payload + layers.l4_payload_len);
        }
    } else if (layers.l4_protocol == 17) { // UDP
        // UDP header is at layers.l4_header, checksum is at bytes 6-7
        if (layers.l4_header_len >= 8) {
            // Copy UDP header excluding checksum (bytes 6-7)
            hash_data.insert(hash_data.end(), layers.l4_header, layers.l4_header + 6);
            // Skip checksum bytes 6-7, but UDP header is only 8 bytes total
        }
        // Add UDP payload
        if (layers.l4_payload_len > 0) {
            hash_data.insert(hash_data.end(), layers.l4_payload, layers.l4_payload + layers.l4_payload_len);
        }
    } else {
        // For other protocols, hash L4 header + payload as-is
        if (layers.l4_header_len > 0) {
            hash_data.insert(hash_data.end(), layers.l4_header, layers.l4_header + layers.l4_header_len);
        }
        if (layers.l4_payload_len > 0) {
            hash_data.insert(hash_data.end(), layers.l4_payload, layers.l4_payload + layers.l4_payload_len);
        }
    }
    
    // Calculate hash
    std::hash<std::string> hasher;
    std::string hash_str(reinterpret_cast<const char*>(hash_data.data()), hash_data.size());
    return static_cast<uint64_t>(hasher(hash_str));
}

// Create a magic MAC watermark packet for S-Flow processing  
static std::unique_ptr<SFlowPacket> create_watermark_packet(const uint8_t* frame, uint32_t len,
                                                          uint64_t timestamp_ns, bool has_timestamp,
                                                          const uint8_t* magic_mac) {
    // Skip PTP packets (EtherType 0x88f7) - never watermark them
    uint16_t ethertype = 0;
    if (parse_ethertype_vlan_aware(frame, len, ethertype) && ethertype == 0x88f7) {
        return nullptr;  // Don't create watermark for PTP packets
    }
    
    // Parse packet layers
    PacketLayers layers = parse_packet_layers(frame, len);
    if (!layers.valid) {
        LOG(LogLevel::WARN, "Failed to parse packet for watermarking, skipping");
        return nullptr;
    }
    
    // Calculate hash of original packet
    uint64_t packet_hash = calculate_packet_hash(frame, len);
    
    // Create watermark payload: [hash:8][timestamp:8] = 16 bytes
    const uint32_t watermark_payload_size = 16;
    std::vector<uint8_t> watermark_payload(watermark_payload_size);
    
    // Pack hash and timestamp in network byte order
    uint64_t hash_be = htobe64(packet_hash);
    uint64_t timestamp_be = htobe64(timestamp_ns);
    std::memcpy(watermark_payload.data(), &hash_be, 8);
    std::memcpy(watermark_payload.data() + 8, &timestamp_be, 8);
    
    // Calculate watermark packet size: headers + watermark payload
    uint32_t headers_size = layers.eth_header_len + layers.ip_header_len + layers.l4_header_len;
    uint32_t watermark_packet_size = headers_size + watermark_payload_size;
    std::vector<uint8_t> watermark_frame(watermark_packet_size);
    
    // Copy all headers (Ethernet + IP + L4)
    std::memcpy(watermark_frame.data(), frame, headers_size);
    
    // Replace destination MAC with magic MAC address
    std::memcpy(watermark_frame.data(), magic_mac, 6);
    
    // Append watermark payload
    std::memcpy(watermark_frame.data() + headers_size, watermark_payload.data(), watermark_payload_size);
    
    // Update IP length field based on IP version
    if (layers.ip_version == 4) {
        // Update IPv4 total length field
        uint16_t ip_total_len = layers.ip_header_len + layers.l4_header_len + watermark_payload_size;
        uint16_t ip_total_len_be = htons(ip_total_len);
        std::memcpy(watermark_frame.data() + layers.eth_header_len + 2, &ip_total_len_be, 2);
    } else if (layers.ip_version == 6) {
        // Update IPv6 payload length field
        uint16_t ipv6_payload_len = layers.l4_header_len + watermark_payload_size;
        uint16_t ipv6_payload_len_be = htons(ipv6_payload_len);
        std::memcpy(watermark_frame.data() + layers.eth_header_len + 4, &ipv6_payload_len_be, 2);
    }
    
    LOG(LogLevel::DEBUG, "Watermark packet: hash=0x%016lX timestamp=%lu payload_size=%u magic_mac=%02X:%02X:%02X:%02X:%02X:%02X IPv%u",
        packet_hash, timestamp_ns, watermark_payload_size, 
        magic_mac[0], magic_mac[1], magic_mac[2], magic_mac[3], magic_mac[4], magic_mac[5], layers.ip_version);
    
    return std::make_unique<SFlowPacket>(watermark_frame.data(), watermark_packet_size, timestamp_ns, has_timestamp);
}

static std::unique_ptr<SFlowPacket> process_sflow_sample(const char* tag, const uint8_t* frame, uint32_t len, 
                                                        uint16_t ethertype, const SFlowConfig& config, 
                                                        SFlowState& state, uint64_t timestamp_ns = 0, bool has_timestamp = false, bool is_hw_timestamp = false) {
    state.sampled_count++;
    
    if (has_timestamp) {
        const char* ts_type = is_hw_timestamp ? "HW" : "SW";
        LOG(LogLevel::INFO, "[%s SFLOW] Sample #%u: len=%u ethertype=0x%04x (%s) timestamp=%lu ns (%s)",
            tag, state.sampled_count, len, ethertype, ethertype_to_str(ethertype),
            timestamp_ns, ts_type);
    } else {
        LOG(LogLevel::INFO, "[%s SFLOW] Sample #%u: len=%u ethertype=0x%04x (%s) timestamp=none",
            tag, state.sampled_count, len, ethertype, ethertype_to_str(ethertype));
    }
    
    // Create watermark packet with magic MAC address (works for any protocol)
    LOG(LogLevel::INFO, "[%s SFLOW] Creating watermark packet with magic MAC", tag);
    return create_watermark_packet(frame, len, timestamp_ns, has_timestamp, config.dest_mac);
}

// -----------------------------------------------------------------------------
// S-Flow processing thread
// -----------------------------------------------------------------------------
void sflow_processing_worker(const char* tag,
                            ThreadSafeQueue<SFlowInputPacket>& input_queue,
                            ThreadSafeQueue<std::unique_ptr<SFlowPacket>>& output_queue,
                            const SFlowConfig& config,
                            SFlowState& state,
                            std::atomic<bool>& running,
                            int cpu_pin) {
    if (cpu_pin >= 0) {
        if (pin_current_thread_to_cpu(cpu_pin) == 0) {
            LOG(LogLevel::INFO, "[%s SFLOW-PROC] pinned to CPU %d", tag, cpu_pin);
        }
    }

    LOG(LogLevel::INFO, "[%s SFLOW-PROC] Processing thread started", tag);

    while (running.load(std::memory_order_relaxed)) {
        SFlowInputPacket input_packet{nullptr, 0, 0}; // dummy initialization
        
        // Wait for packets to process (100ms timeout to check running flag)
        if (input_queue.wait_and_pop(input_packet, 100)) {
            // Process the S-Flow sample
            auto sflow_pkt = process_sflow_sample(tag, 
                                                input_packet.data.data(), 
                                                input_packet.length,
                                                input_packet.ethertype, 
                                                config, 
                                                state,
                                                input_packet.timestamp_ns, 
                                                input_packet.has_timestamp, 
                                                input_packet.is_hw_timestamp);
            
            if (sflow_pkt) {
                // Queue the processed packet for transmission
                output_queue.push(std::move(sflow_pkt));
            }
        }
    }

    LOG(LogLevel::INFO, "[%s SFLOW-PROC] Processing thread shutting down", tag);
}

// -----------------------------------------------------------------------------
// Forwarding: RX -> copy -> TX -> recycle (with S-Flow sampling)
// -----------------------------------------------------------------------------
void forward_step(const char* tag,
                  XskEndpoint& in_ep, UmemArea& in_umem,
                  XskEndpoint& out_ep, UmemArea& out_umem,
                  bool debug_print = false,
                  const SFlowConfig* sflow_config = nullptr,
                  SFlowState* sflow_state = nullptr,
                  ThreadSafeQueue<SFlowInputPacket>* sflow_input_queue = nullptr,
                  ThreadSafeQueue<std::unique_ptr<SFlowPacket>>* sflow_output_queue = nullptr)
{
    static constexpr uint32_t BATCH = 64;

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
    for (unsigned int i = 0; i < rcvd; ++i) {
        const struct xdp_desc* rxd = xsk_ring_cons__rx_desc(&in_ep.rx, rx_idx + i);
        rx_addrs[i] = rxd->addr;
        rx_lens[i]  = rxd->len;
    }

    // Debug: log EtherType per packet
    if (debug_print) {
        for (unsigned int i = 0; i < rcvd; ++i) {
            const uint8_t* frame = umem_ptr(in_umem, rx_addrs[i]);
            uint16_t et = 0;
            if (parse_ethertype_vlan_aware(frame, rx_lens[i], et)) {
                LOG(LogLevel::DEBUG, "[%s RX] len=%u ethertype=0x%04x (%s)",
                    tag, rx_lens[i], et, ethertype_to_str(et));
            } else {
                LOG(LogLevel::DEBUG, "[%s RX] len=%u ethertype=? (frame too short/malformed)",
                    tag, rx_lens[i]);
            }
        }
    }
    
    // S-Flow sampling (only for A→B direction indicated by tag)
    if (sflow_config && sflow_config->is_enabled() && sflow_state && 
        sflow_config->sampling_rate > 0 && 
        std::strcmp(tag, "A→B") == 0 && sflow_input_queue) {
        
        for (unsigned int i = 0; i < rcvd; ++i) {
            sflow_state->packet_count++;
            
            // Check if this packet should be sampled
            if ((sflow_state->packet_count % sflow_config->sampling_rate) == 0) {
                const uint8_t* frame = umem_ptr(in_umem, rx_addrs[i]);
                uint16_t et = 0;
                
                if (get_ethertype(frame, rx_lens[i], et, sflow_config->skip_vlan)) {
                    // Skip PTP packets (EtherType 0x88f7) - never sample them
                    if (et == 0x88f7) {
                        continue; // Skip sampling for PTP packets
                    }
                    
                    // Check if this EtherType is in our sample list
                    for (uint16_t target_et : sflow_config->ethertypes) {
                        if (et == target_et) {
                            // Try to extract hardware timestamp for 1588 support
                            uint64_t timestamp_ns = 0;
                            bool has_timestamp = false;
                            bool is_hw_timestamp = false;
                            
                            // First try to get hardware timestamp from PTP hardware clock
                            if (get_ptp_hw_timestamp(timestamp_ns)) {
                                has_timestamp = true;
                                is_hw_timestamp = true;
                            } else if (extract_hw_timestamp(in_ep.fd, timestamp_ns)) {
                                has_timestamp = true;
                                is_hw_timestamp = true;
                            } else {
                                // Fallback to system time if hardware timestamp not available
                                struct timespec ts;
                                if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
                                    timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
                                    has_timestamp = true;
                                    is_hw_timestamp = false;
                                }
                            }
                            
                            // Queue packet for S-Flow processing
                            SFlowInputPacket input_packet(frame, rx_lens[i], et, 
                                                        timestamp_ns, has_timestamp, is_hw_timestamp);
                            sflow_input_queue->push(std::move(input_packet));
                            break; // Only sample once per packet even if multiple matches
                        }
                    }
                }
            }
        }
    }

    // 3) Reserve TX slots on output side
    uint32_t tx_idx = 0;
    unsigned int tx_space = xsk_ring_prod__reserve(&out_ep.tx, rcvd, &tx_idx);
    unsigned int to_tx = std::min(rcvd, tx_space);
    if (to_tx == 0) {
        // Release RX and recycle RX frames (no TX space)
        xsk_ring_cons__release(&in_ep.rx, rcvd);

        uint32_t f_idx = 0;
        unsigned int can_fill = xsk_ring_prod__reserve(&in_umem.fill, rcvd, &f_idx);
        unsigned int to_fill = std::min(rcvd, can_fill);
        for (unsigned int i = 0; i < to_fill; ++i) {
            *xsk_ring_prod__fill_addr(&in_umem.fill, f_idx + i) = rx_addrs[i];
        }
        if (to_fill) xsk_ring_prod__submit(&in_umem.fill, to_fill);
        return;
    }

    // 4) Copy packets into output UMEM frames and fill TX descriptors
    unsigned int actually_tx = 0;
    for (unsigned int i = 0; i < to_tx; ++i) {
        uint64_t out_addr = 0;
        if (!alloc_frame(out_umem, out_addr)) {
            // Out of output frames unexpectedly; stop here
            break;
        }

        const uint32_t len = rx_lens[i];
        uint8_t* src = umem_ptr(in_umem,  rx_addrs[i]);
        uint8_t* dst = umem_ptr(out_umem, out_addr);

        std::memcpy(dst, src, len);

        struct xdp_desc* txd = xsk_ring_prod__tx_desc(&out_ep.tx, tx_idx + i);
        txd->addr = out_addr;
        txd->len  = len;

        actually_tx++;
    }

    // 5) Submit TX and kick
    if (actually_tx) {
        xsk_ring_prod__submit(&out_ep.tx, actually_tx);
        (void)sendto(out_ep.fd, nullptr, 0, MSG_DONTWAIT, nullptr, 0); // TX kick
    }
    
    // 5.5) Send S-Flow packets from processing queue if any are ready
    if (sflow_output_queue) {
        std::unique_ptr<SFlowPacket> sflow_pkt;
        while (sflow_output_queue->try_pop(sflow_pkt)) {
            
            // Try to reserve one more TX slot for the S-Flow packet
            uint32_t sflow_tx_idx = 0;
            unsigned int sflow_tx_space = xsk_ring_prod__reserve(&out_ep.tx, 1, &sflow_tx_idx);
            
            if (sflow_tx_space > 0) {
                uint64_t sflow_out_addr = 0;
                if (alloc_frame(out_umem, sflow_out_addr)) {
                    // Copy S-Flow packet data to output UMEM
                    uint8_t* sflow_dst = umem_ptr(out_umem, sflow_out_addr);
                    std::memcpy(sflow_dst, sflow_pkt->data.data(), sflow_pkt->length);
                    
                    // Fill TX descriptor for S-Flow packet
                    struct xdp_desc* sflow_txd = xsk_ring_prod__tx_desc(&out_ep.tx, sflow_tx_idx);
                    sflow_txd->addr = sflow_out_addr;
                    sflow_txd->len = sflow_pkt->length;
                    
                    // Submit S-Flow packet
                    xsk_ring_prod__submit(&out_ep.tx, 1);
                    (void)sendto(out_ep.fd, nullptr, 0, MSG_DONTWAIT, nullptr, 0); // TX kick
                    
                    if (sflow_pkt->has_timestamp) {
                        LOG(LogLevel::DEBUG, "[%s] S-Flow packet sent: len=%u timestamp=%lu ns", 
                            tag, sflow_pkt->length, sflow_pkt->timestamp_ns);
                    } else {
                        LOG(LogLevel::DEBUG, "[%s] S-Flow packet sent: len=%u timestamp=none", tag, sflow_pkt->length);
                    }
                } else {
                    LOG(LogLevel::WARN, "[%s] Failed to allocate frame for S-Flow packet", tag);
                    // Note: Cannot cancel reserved TX slot in libxdp, will be unused
                }
            } else {
                LOG(LogLevel::WARN, "[%s] No TX space available for S-Flow packet", tag);
                // Put the packet back in the queue for later processing
                // Note: We can't put it back easily without copying, so we'll just drop it
                // In a production system, you might want a more sophisticated retry mechanism
                break; // Stop processing more packets from queue
            }
        }
    }

    // 6) Release RX descriptors we consumed
    xsk_ring_cons__release(&in_ep.rx, rcvd);

    // 7) Recycle RX frames back to input fill ring
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
// Worker thread: optional pin + poll + forward in one direction
// -----------------------------------------------------------------------------
void forward_worker(const char* tag,
                    XskEndpoint* in_ep, UmemArea* in_umem,
                    XskEndpoint* out_ep, UmemArea* out_umem,
                    std::atomic<bool>* running,
                    bool debug_print,
                    int cpu_pin, /* -1 = no pin */
                    const SFlowConfig* sflow_config = nullptr,
                    SFlowState* sflow_state = nullptr,
                    ThreadSafeQueue<SFlowInputPacket>* sflow_input_queue = nullptr,
                    ThreadSafeQueue<std::unique_ptr<SFlowPacket>>* sflow_output_queue = nullptr)
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
        forward_step(tag, *in_ep, *in_umem, *out_ep, *out_umem, debug_print, sflow_config, sflow_state, sflow_input_queue, sflow_output_queue);
    }
}

// -----------------------------------------------------------------------------
// Arg parsing
// -----------------------------------------------------------------------------
struct Cmd {
    const char* devA = nullptr;
    const char* devB = nullptr;
    int cpu_forwarding_cores[2] = {-1, -1}; // Support up to 2 cores for forwarding
    int cpu_return = -1;
    SFlowConfig sflow;
    LogLevel log_level = LogLevel::WARN;  // Default to WARN
    bool verbose = false;                 // Default to not verbose
};

static void print_usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " <netdev_A> <netdev_B> [options]\n"
        << "\nCPU Pinning:\n"
        << "  --cpu.forwarding N[,M]  Pin A→B worker thread to CPU N (optionally second core M)\n"
        << "  --cpu.return M          Pin B→A worker thread to CPU M\n"
        << "\nS-Flow Sampling (A→B traffic only):\n"
        << "  --sample.sampling N     Sample 1 out of every N packets (0=disabled, e.g. 1000)\n"
        << "  --sample.ethertypes L   Comma-separated EtherTypes to sample (e.g. 0x800,0x86DD)\n"
        << "  --sample.skip_vlan B    Skip VLAN tags to find EtherType (true/false, default: true)\n"
        << "  --sample.dest_mac MAC   Destination MAC for watermark packets (e.g. 02:00:00:00:00:01)\n"
        << "\nLogging:\n"
        << "  --log-level LEVEL       Set log level: DEBUG, INFO, WARN, ERROR (default: WARN)\n"
        << "  --verbose               Enable per-packet debug prints (EtherType + length)\n"
        << "\nExamples:\n"
        << "  " << prog << " eth0 eth1 --cpu.forwarding 2 --cpu.return 3\n"
        << "  " << prog << " eth0 eth1 --sample.sampling 1000 --sample.ethertypes=0x800,0x86DD\n"
        << "  " << prog << " eth0 eth1 --sample.sampling 500 --sample.dest_mac=02:00:00:00:00:01 --log-level INFO\n";
}

static bool parse_args(int argc, char** argv, Cmd& cmd) {
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
        } else if (option == "--sample.sampling") {
            std::string rate_str = (eq_pos != std::string::npos) ? value : 
                                  (i + 1 < argc ? argv[++i] : "");
            if (rate_str.empty()) {
                std::cerr << "Missing value for --sample.sampling\n";
                return false;
            }
            int rate = std::atoi(rate_str.c_str());
            if (rate < 0) {
                std::cerr << "Invalid sampling rate: " << rate << " (must be >= 0, 0 = disabled)\n";
                return false;
            }
            cmd.sflow.sampling_rate = static_cast<uint32_t>(rate);
        } else if (option == "--sample.ethertypes") {
            std::string types_str = (eq_pos != std::string::npos) ? value : 
                                   (i + 1 < argc ? argv[++i] : "");
            if (types_str.empty()) {
                std::cerr << "Missing value for --sample.ethertypes\n";
                return false;
            }
            if (!parse_ethertypes(types_str.c_str(), cmd.sflow.ethertypes)) {
                std::cerr << "Failed to parse EtherTypes\n";
                return false;
            }
        } else if (option == "--sample.skip_vlan") {
            std::string skip_str = (eq_pos != std::string::npos) ? value : 
                                  (i + 1 < argc ? argv[++i] : "");
            if (skip_str.empty()) {
                std::cerr << "Missing value for --sample.skip_vlan\n";
                return false;
            }
            if (skip_str == "true" || skip_str == "1") {
                cmd.sflow.skip_vlan = true;
            } else if (skip_str == "false" || skip_str == "0") {
                cmd.sflow.skip_vlan = false;
            } else {
                std::cerr << "Invalid skip_vlan value: " << skip_str << " (use true/false)\n";
                return false;
            }
        } else if (option == "--sample.dest_mac") {
            std::string mac_str = (eq_pos != std::string::npos) ? value : 
                                 (i + 1 < argc ? argv[++i] : "");
            if (mac_str.empty()) {
                std::cerr << "Missing value for --sample.dest_mac\n";
                return false;
            }
            if (!parse_mac_address(mac_str.c_str(), cmd.sflow.dest_mac)) {
                std::cerr << "Failed to parse destination MAC address\n";
                return false;
            }
        } else if (option == "--log-level") {
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
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            return false;
        }
    }
    
    // Validate S-Flow config - only validate when sampling is actually enabled
    if (cmd.sflow.sampling_rate > 0 && cmd.sflow.ethertypes.empty()) {
        std::cerr << "S-Flow sampling enabled but no EtherTypes specified\n";
        return false;
    }
    // Note: Allow ethertypes with sampling_rate=0 since 0 means disabled anyway
    
    return true;
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------
int main(int argc, char** argv) {
    Cmd cmd {};
    if (!parse_args(argc, argv, cmd)) {
        print_usage(argv[0]);
        return 1;
    }

    const char* devA = cmd.devA;
    const char* devB = cmd.devB;

    // Apply log level and verbose settings
    set_log_level(cmd.log_level);
    set_verbose_mode(cmd.verbose);

    std::cout << "S-Flow Packet Forwarder with AF_XDP\n";
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
    const uint32_t FRAME_COUNT = 8192; // tune as needed
    const uint32_t FRAME_SIZE  = 2048; // must hold your MTU (1500 -> OK)
    const uint32_t HEADROOM    = 0;
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

    bool A_zerocopy=false, A_skb=false;
    if (create_xsk_with_fallback(devA, epA, umemA, base_cfg, A_zerocopy, A_skb, /*queue_id=*/0, /*allow_skb_fallback=*/true)) {
        xsk_umem__delete(umemB.umem); free(umemB.buffer);
        xsk_umem__delete(umemA.umem); free(umemA.buffer);
        return 1;
    }

    bool B_zerocopy=false, B_skb=false;
    if (create_xsk_with_fallback(devB, epB, umemB, base_cfg, B_zerocopy, B_skb, /*queue_id=*/0, /*allow_skb_fallback=*/true)) {
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

    // --- S-Flow configuration logging ---
    if (cmd.sflow.is_enabled()) {
        LOG(LogLevel::INFO, "S-Flow sampling enabled for A→B traffic:");
        LOG(LogLevel::INFO, "  - Sampling rate: 1 in %u packets", cmd.sflow.sampling_rate);
        LOG(LogLevel::INFO, "  - Skip VLAN tags: %s", cmd.sflow.skip_vlan ? "true" : "false");
        LOG(LogLevel::INFO, "  - Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X", 
            cmd.sflow.dest_mac[0], cmd.sflow.dest_mac[1], cmd.sflow.dest_mac[2],
            cmd.sflow.dest_mac[3], cmd.sflow.dest_mac[4], cmd.sflow.dest_mac[5]);
        std::stringstream ss;
        for (size_t i = 0; i < cmd.sflow.ethertypes.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << "0x" << std::hex << std::uppercase << cmd.sflow.ethertypes[i];
        }
        LOG(LogLevel::INFO, "  - EtherTypes: %s", ss.str().c_str());
    }
    
    LOG(LogLevel::INFO, "Sockets created and rings mapped. Starting bidirectional forwarding (multi-threaded)...");

    // --- S-Flow state and queues (only needed for A→B direction) ---
    SFlowState sflow_state_ab {};
    ThreadSafeQueue<SFlowInputPacket> sflow_input_queue;
    ThreadSafeQueue<std::unique_ptr<SFlowPacket>> sflow_output_queue;
    
    // Determine S-Flow processing CPU
    int sflow_processing_cpu = -1; // no pinning by default
    if (cmd.sflow.is_enabled()) {
        if (cmd.cpu_forwarding_cores[1] >= 0) {
            // Two cores specified: 2nd core for S-Flow processing
            sflow_processing_cpu = cmd.cpu_forwarding_cores[1];
            LOG(LogLevel::INFO, "S-Flow processing will use CPU %d (separate from forwarding)", sflow_processing_cpu);
        } else if (cmd.cpu_forwarding_cores[0] >= 0) {
            // One core specified: same core as forwarding
            sflow_processing_cpu = cmd.cpu_forwarding_cores[0];
            LOG(LogLevel::INFO, "S-Flow processing will use CPU %d (shared with forwarding)", sflow_processing_cpu);
        }
    }
    
    // --- Launch S-Flow processing thread (if enabled) ---
    std::unique_ptr<std::thread> t_sflow_proc;
    if (cmd.sflow.is_enabled()) {
        t_sflow_proc = std::make_unique<std::thread>(
            sflow_processing_worker, "A→B",
            std::ref(sflow_input_queue),
            std::ref(sflow_output_queue),
            std::ref(cmd.sflow),
            std::ref(sflow_state_ab),
            std::ref(g_running),
            sflow_processing_cpu);
    }
    
    // --- Launch one worker thread per direction, with optional CPU pinning ---
    std::thread t_ab(
        forward_worker, "A→B",
        &epA, &umemA,
        &epB, &umemB,
        &g_running, verbose,
        cmd.cpu_forwarding_cores[0], /* pin id or -1 */
        cmd.sflow.is_enabled() ? &cmd.sflow : nullptr,
        cmd.sflow.is_enabled() ? &sflow_state_ab : nullptr,
        cmd.sflow.is_enabled() ? &sflow_input_queue : nullptr,
        cmd.sflow.is_enabled() ? &sflow_output_queue : nullptr);

    std::thread t_ba(
        forward_worker, "B→A",
        &epB, &umemB,
        &epA, &umemA,
        &g_running, verbose,
        cmd.cpu_return, /* pin id or -1 */
        nullptr, /* no S-Flow for B→A */
        nullptr,
        nullptr, /* no S-Flow queues for B→A */
        nullptr);

    // Wait for Ctrl-C
    t_ab.join();
    t_ba.join();
    if (t_sflow_proc) {
        t_sflow_proc->join();
    }

    // Cleanup
    xsk_socket__delete(epB.xsk);
    xsk_socket__delete(epA.xsk);
    xsk_umem__delete(umemB.umem); free(umemB.buffer);
    xsk_umem__delete(umemA.umem); free(umemA.buffer);
    return 0;
}