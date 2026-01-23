#include "bitw_common.h"

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

// Check if a packet is TCP by examining the IP protocol field
static inline bool is_tcp_packet(const uint8_t* frame, uint32_t len) {
    PacketLayers layers = parse_packet_layers(frame, len, 6); // 6 = TCP protocol
    return layers.valid && layers.l4_protocol == 6;
}

// Create a tagged TCP packet copy for S-Flow processing
static std::unique_ptr<SFlowPacket> create_tagged_tcp_packet(const uint8_t* frame, uint32_t len, 
                                                           uint64_t timestamp_ns, bool has_timestamp) {
    // Parse packet layers
    PacketLayers layers = parse_packet_layers(frame, len, 6); // 6 = TCP protocol
    if (!layers.valid) {
        LOG(LogLevel::WARN, "Failed to parse TCP packet for tagging, returning original");
        return std::make_unique<SFlowPacket>(frame, len, timestamp_ns, has_timestamp);
    }
    
    // Calculate hash of original packet
    uint64_t packet_hash = calculate_packet_hash(frame, len);
    
    // Create new payload: [hash:8][timestamp:8] = 16 bytes
    const uint32_t new_payload_size = 16;
    std::vector<uint8_t> new_payload(new_payload_size);
    
    // Pack hash and timestamp in network byte order
    uint64_t hash_be = htobe64(packet_hash);
    uint64_t timestamp_be = htobe64(timestamp_ns);
    std::memcpy(new_payload.data(), &hash_be, 8);
    std::memcpy(new_payload.data() + 8, &timestamp_be, 8);
    
    // Calculate new packet size: headers + new payload
    uint32_t headers_size = layers.eth_header_len + layers.ip_header_len + layers.l4_header_len;
    uint32_t new_packet_size = headers_size + new_payload_size;
    std::vector<uint8_t> modified_frame(new_packet_size);
    
    // Copy all headers (Ethernet + IP + TCP)
    std::memcpy(modified_frame.data(), frame, headers_size);
    
    // Append new payload
    std::memcpy(modified_frame.data() + headers_size, new_payload.data(), new_payload_size);
    
    // Update IP length field based on IP version
    if (layers.ip_version == 4) {
        // Update IPv4 total length field
        uint16_t ip_total_len = layers.ip_header_len + layers.l4_header_len + new_payload_size;
        uint16_t ip_total_len_be = htons(ip_total_len);
        std::memcpy(modified_frame.data() + layers.eth_header_len + 2, &ip_total_len_be, 2);
    } else if (layers.ip_version == 6) {
        // Update IPv6 payload length field
        uint16_t ipv6_payload_len = layers.l4_header_len + new_payload_size;
        uint16_t ipv6_payload_len_be = htons(ipv6_payload_len);
        std::memcpy(modified_frame.data() + layers.eth_header_len + 4, &ipv6_payload_len_be, 2);
    }
    
    // Set TCP Reserved bits with random tag
    uint32_t reserved_byte_offset = layers.eth_header_len + layers.ip_header_len + 12; // TCP flags byte
    static thread_local std::random_device rd;
    static thread_local std::mt19937 gen(rd());
    static thread_local std::uniform_int_distribution<> dis(1, 15);
    uint8_t random_tag = static_cast<uint8_t>(dis(gen));
    
    uint8_t tcp_flags_byte = modified_frame[reserved_byte_offset];
    tcp_flags_byte = (tcp_flags_byte & 0x0F) | (random_tag << 4);
    modified_frame[reserved_byte_offset] = tcp_flags_byte;
    
    LOG(LogLevel::DEBUG, "Tagged TCP packet: hash=0x%016lX timestamp=%lu payload_size=%u reserved_bits=0x%02X IPv%u",
        packet_hash, timestamp_ns, new_payload_size, random_tag, layers.ip_version);
    
    return std::make_unique<SFlowPacket>(modified_frame.data(), new_packet_size, timestamp_ns, has_timestamp);
}

static std::unique_ptr<SFlowPacket> process_sflow_sample(const char* tag, const uint8_t* frame, uint32_t len, 
                                                        uint16_t ethertype, const SFlowConfig& config, 
                                                        SFlowState& state, uint64_t timestamp_ns = 0, bool has_timestamp = false, bool is_hw_timestamp = false) {
    state.sampled_count++;
    
    if (has_timestamp) {
        const char* ts_type = is_hw_timestamp ? "HW" : "SW";
        LOG(LogLevel::INFO, "[%s SFLOW] Sample #%u: len=%u ethertype=0x%04x (%s) timestamp=%lu ns (%s) skip_vlan=%s",
            tag, state.sampled_count, len, ethertype, ethertype_to_str(ethertype),
            timestamp_ns, ts_type, config.skip_vlan ? "true" : "false");
    } else {
        LOG(LogLevel::INFO, "[%s SFLOW] Sample #%u: len=%u ethertype=0x%04x (%s) timestamp=none skip_vlan=%s",
            tag, state.sampled_count, len, ethertype, ethertype_to_str(ethertype),
            config.skip_vlan ? "true" : "false");
    }
    
    // Create a copy of the packet to be sent after the original
    // Check if this is a TCP packet and handle it specially
    if (is_tcp_packet(frame, len)) {
        LOG(LogLevel::INFO, "[%s SFLOW] TCP packet detected, creating tagged copy", tag);
        return create_tagged_tcp_packet(frame, len, timestamp_ns, has_timestamp);
    } else {
        // For non-TCP packets, create a standard copy
        // LOG(LogLevel::INFO, "[%s SFLOW] Creating packet copy for transmission", tag);
        // return std::make_unique<SFlowPacket>(frame, len, timestamp_ns, has_timestamp);
        return nullptr;
    }
}

// -----------------------------------------------------------------------------
// Forwarding: RX -> copy -> TX -> recycle (with S-Flow sampling)
// -----------------------------------------------------------------------------
void forward_step(const char* tag,
                  XskEndpoint& in_ep, UmemArea& in_umem,
                  XskEndpoint& out_ep, UmemArea& out_umem,
                  bool debug_print = false,
                  const SFlowConfig* sflow_config = nullptr,
                  SFlowState* sflow_state = nullptr)
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
    std::vector<std::unique_ptr<SFlowPacket>> sflow_packets;
    if (sflow_config && sflow_config->is_enabled() && sflow_state && 
        sflow_config->sampling_rate > 0 && 
        std::strcmp(tag, "A→B") == 0) {
        
        for (unsigned int i = 0; i < rcvd; ++i) {
            sflow_state->packet_count++;
            
            // Check if this packet should be sampled
            if ((sflow_state->packet_count % sflow_config->sampling_rate) == 0) {
                const uint8_t* frame = umem_ptr(in_umem, rx_addrs[i]);
                uint16_t et = 0;
                
                if (get_ethertype(frame, rx_lens[i], et, sflow_config->skip_vlan)) {
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
                            
                            auto sflow_pkt = process_sflow_sample(tag, frame, rx_lens[i], et, *sflow_config, *sflow_state,
                                                                timestamp_ns, has_timestamp, is_hw_timestamp);
                            if (sflow_pkt) {
                                sflow_packets.push_back(std::move(sflow_pkt));
                            }
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
    
    // 5.5) Send S-Flow packets if any were generated
    if (!sflow_packets.empty()) {
        LOG(LogLevel::DEBUG, "[%s] Sending %zu S-Flow packet copies", tag, sflow_packets.size());
        
        for (const auto& sflow_pkt : sflow_packets) {
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
                    SFlowState* sflow_state = nullptr)
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
        forward_step(tag, *in_ep, *in_umem, *out_ep, *out_umem, debug_print, sflow_config, sflow_state);
    }
}

// -----------------------------------------------------------------------------
// Arg parsing
// -----------------------------------------------------------------------------
struct Cmd {
    const char* devA = nullptr;
    const char* devB = nullptr;
    int cpu_a = -1;
    int cpu_b = -1;
    SFlowConfig sflow;
};

static void print_usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " <netdev_A> <netdev_B> [options]\n"
        << "\nCPU Pinning:\n"
        << "  --cpu-a N               Pin A→B worker thread to CPU N\n"
        << "  --cpu-b M               Pin B→A worker thread to CPU M\n"
        << "\nS-Flow Sampling (A→B traffic only):\n"
        << "  --sample.sampling N     Sample 1 out of every N packets (0=disabled, e.g. 1000)\n"
        << "  --sample.ethertypes L   Comma-separated EtherTypes to sample (e.g. 0x800,0x86DD)\n"
        << "  --sample.skip_vlan B    Skip VLAN tags to find EtherType (true/false, default: true)\n"
        << "\nEnvironment:\n"
        << "  BUMP_VERBOSE=1          Enable per-packet debug prints (EtherType + length)\n"
        << "\nExamples:\n"
        << "  " << prog << " eth0 eth1 --cpu-a 2 --cpu-b 3\n"
        << "  " << prog << " PF0 PF1 --sample.sampling 1000 --sample.ethertypes=0x800,0x86DD\n"
        << "  " << prog << " PF0 PF1 --sample.sampling 500 --sample.ethertypes=0x800 --sample.skip_vlan false\n";
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
        
        if (option == "--cpu-a") {
            if (eq_pos != std::string::npos) {
                cmd.cpu_a = std::atoi(value.c_str());
            } else if (i + 1 < argc) {
                cmd.cpu_a = std::atoi(argv[++i]);
            } else {
                std::cerr << "Missing value for --cpu-a\n";
                return false;
            }
        } else if (option == "--cpu-b") {
            if (eq_pos != std::string::npos) {
                cmd.cpu_b = std::atoi(value.c_str());
            } else if (i + 1 < argc) {
                cmd.cpu_b = std::atoi(argv[++i]);
            } else {
                std::cerr << "Missing value for --cpu-b\n";
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

    std::cout << "S-Flow Packet Forwarder with AF_XDP\n";
    std::cout << "Device A: " << devA << "\n";
    std::cout << "Device B: " << devB << "\n";
    if (cmd.cpu_a >= 0) LOG(LogLevel::INFO, "Pin A→B thread to CPU %d", cmd.cpu_a);
    if (cmd.cpu_b >= 0) LOG(LogLevel::INFO, "Pin B→A thread to CPU %d", cmd.cpu_b);

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
    const bool verbose = (std::getenv("BUMP_VERBOSE") != nullptr);

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
        std::stringstream ss;
        for (size_t i = 0; i < cmd.sflow.ethertypes.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << "0x" << std::hex << std::uppercase << cmd.sflow.ethertypes[i];
        }
        LOG(LogLevel::INFO, "  - EtherTypes: %s", ss.str().c_str());
    }
    
    LOG(LogLevel::INFO, "Sockets created and rings mapped. Starting bidirectional forwarding (multi-threaded)...");

    // --- S-Flow state (only needed for A→B direction) ---
    SFlowState sflow_state_ab {};
    
    // --- Launch one worker thread per direction, with optional CPU pinning ---
    std::thread t_ab(
        forward_worker, "A→B",
        &epA, &umemA,
        &epB, &umemB,
        &g_running, verbose,
        cmd.cpu_a, /* pin id or -1 */
        cmd.sflow.is_enabled() ? &cmd.sflow : nullptr,
        cmd.sflow.is_enabled() ? &sflow_state_ab : nullptr);

    std::thread t_ba(
        forward_worker, "B→A",
        &epB, &umemB,
        &epA, &umemA,
        &g_running, verbose,
        cmd.cpu_b, /* pin id or -1 */
        nullptr, /* no S-Flow for B→A */
        nullptr);

    // Wait for Ctrl-C
    t_ab.join();
    t_ba.join();

    // Cleanup
    xsk_socket__delete(epB.xsk);
    xsk_socket__delete(epA.xsk);
    xsk_umem__delete(umemB.umem); free(umemB.buffer);
    xsk_umem__delete(umemA.umem); free(umemA.buffer);
    return 0;
}