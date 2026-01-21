#include "bitw_common.h"

// -----------------------------------------------------------------------------
// Watermark detection and filtering functions
// -----------------------------------------------------------------------------

// Check if a packet is watermarked by examining TCP Reserved bits and payload
static bool is_watermarked_packet(const PacketLayers& layers) {
    if (!layers.valid || layers.l4_protocol != 6) { // Only TCP packets can be watermarked
        return false;
    }
    
    // Check TCP Reserved bits (upper 4 bits of byte 12 in TCP header)
    uint32_t reserved_byte_offset = 12; // Relative to TCP header start
    if (layers.l4_header_len < 13) return false; // Need at least 13 bytes for flags byte
    
    uint8_t tcp_flags_byte = layers.l4_header[reserved_byte_offset];
    uint8_t reserved_bits = (tcp_flags_byte >> 4) & 0x0F;
    
    // Check if Reserved bits are non-zero (our watermark)
    if (reserved_bits == 0) return false;
    
    // Check if payload matches our watermark format: [hash:8][timestamp:8] = 16 bytes
    if (layers.l4_payload_len != 16) return false;
    
    // Extract hash and timestamp from payload
    uint64_t hash_be, timestamp_be;
    std::memcpy(&hash_be, layers.l4_payload, 8);
    std::memcpy(&timestamp_be, layers.l4_payload + 8, 8);
    
    uint64_t extracted_hash = be64toh(hash_be);
    uint64_t extracted_timestamp = be64toh(timestamp_be);
    
    // Basic sanity checks on extracted values
    // Timestamp should be reasonable (not zero, not too far in future)
    uint64_t current_ns = 0;
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        current_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    }
    
    // Allow timestamps from up to 1 hour ago to 1 minute in future
    uint64_t hour_ns = 3600ULL * 1000000000ULL;
    uint64_t minute_ns = 60ULL * 1000000000ULL;
    
    if (extracted_timestamp == 0 || 
        (current_ns > 0 && 
         (extracted_timestamp < (current_ns - hour_ns) || 
          extracted_timestamp > (current_ns + minute_ns)))) {
        return false;
    }
    
    return true; // Packet appears to be watermarked
}

// Process a detected watermarked packet
static void process_watermarked_packet(const char* tag, const PacketLayers& layers, 
                                     const uint8_t* frame, uint32_t len) {
    // Extract watermark data
    uint64_t hash_be, timestamp_be;
    std::memcpy(&hash_be, layers.l4_payload, 8);
    std::memcpy(&timestamp_be, layers.l4_payload + 8, 8);
    
    uint64_t extracted_hash = be64toh(hash_be);
    uint64_t extracted_timestamp = be64toh(timestamp_be);
    
    // Extract Reserved bits value
    uint8_t tcp_flags_byte = layers.l4_header[12];
    uint8_t reserved_bits = (tcp_flags_byte >> 4) & 0x0F;
    
    // Calculate current time for latency measurement
    uint64_t current_ns = 0;
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        current_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    }
    
    uint64_t latency_ns = (current_ns > extracted_timestamp) ? (current_ns - extracted_timestamp) : 0;
    double latency_ms = static_cast<double>(latency_ns) / 1000000.0;
    
    LOG(LogLevel::INFO, "[%s WATERMARK] Detected packet: hash=0x%016lX timestamp=%lu ns "
                        "reserved_bits=0x%02X latency=%.3f ms IPv%u len=%u",
        tag, extracted_hash, extracted_timestamp, reserved_bits, latency_ms, 
        layers.ip_version, len);
}

// -----------------------------------------------------------------------------
// Filtering: RX -> analyze -> optionally drop watermarked packets
// -----------------------------------------------------------------------------
void filter_step(const char* tag,
                 XskEndpoint& in_ep, UmemArea& in_umem,
                 XskEndpoint& out_ep, UmemArea& out_umem,
                 bool debug_print = false)
{
    static constexpr uint32_t BATCH = 64;
    static uint32_t total_packets = 0;
    static uint32_t watermarked_packets = 0;
    static uint32_t dropped_packets = 0;

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
            
            // Parse packet to check for watermark
            PacketLayers layers = parse_packet_layers(frame, rx_lens[i], 6); // TCP only
            if (layers.valid && is_watermarked_packet(layers)) {
                watermarked_packets++;
                dropped_packets++;
                forward_packet[i] = false; // Drop watermarked packet
                
                process_watermarked_packet(tag, layers, frame, rx_lens[i]);
            }
            
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
        if ((total_packets % 10000) == 0 && total_packets > 0) {
            double drop_rate = (static_cast<double>(dropped_packets) / total_packets) * 100.0;
            LOG(LogLevel::INFO, "[%s STATS] Total: %u, Watermarked: %u, Dropped: %u (%.2f%%)",
                tag, total_packets, watermarked_packets, dropped_packets, drop_rate);
        }
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
                   int cpu_pin)
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
        filter_step(tag, *in_ep, *in_umem, *out_ep, *out_umem, debug_print);
    }
}

// -----------------------------------------------------------------------------
// Arg parsing
// -----------------------------------------------------------------------------
struct FilterCmd {
    const char* devA = nullptr;
    const char* devB = nullptr;
    int cpu_a = -1;
    int cpu_b = -1;
};

static void print_usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " <netdev_A> <netdev_B> [options]\n"
        << "\nWatermark Packet Filter with AF_XDP\n"
        << "Detects and drops TCP packets with watermark signatures (Reserved bits + hash+timestamp payload)\n"
        << "\nCPU Pinning:\n"
        << "  --cpu-a N               Pin A→B worker thread to CPU N\n"
        << "  --cpu-b M               Pin B→A worker thread to CPU M\n"
        << "\nEnvironment:\n"
        << "  BUMP_VERBOSE=1          Enable per-packet debug prints (EtherType + action)\n"
        << "\nExamples:\n"
        << "  " << prog << " eth0 eth1\n"
        << "  " << prog << " PF0 PF1 --cpu-a 2 --cpu-b 3\n"
        << "\nWatermark Detection:\n"
        << "  - Looks for TCP packets with non-zero Reserved bits\n"
        << "  - Expects 16-byte payload containing [hash:8][timestamp:8]\n"
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
    FilterCmd cmd {};
    if (!parse_args(argc, argv, cmd)) {
        print_usage(argv[0]);
        return 1;
    }

    const char* devA = cmd.devA;
    const char* devB = cmd.devB;

    std::cout << "Watermark Packet Filter with AF_XDP\n";
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

    LOG(LogLevel::INFO, "Watermark detection enabled for A→B traffic (TCP Reserved bits + hash+timestamp payload)");
    LOG(LogLevel::INFO, "Sockets created and rings mapped. Starting bidirectional filtering (multi-threaded)...");
    
    // --- Launch one worker thread per direction, with optional CPU pinning ---
    std::thread t_ab(
        filter_worker, "A→B",
        &epA, &umemA,
        &epB, &umemB,
        &g_running, verbose,
        cmd.cpu_a);

    std::thread t_ba(
        filter_worker, "B→A",
        &epB, &umemB,
        &epA, &umemA,
        &g_running, verbose,
        cmd.cpu_b);

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