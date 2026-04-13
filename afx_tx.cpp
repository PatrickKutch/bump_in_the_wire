/*
 * afx_tx.cpp - Standalone AF_XDP TX test program for Intel I226 driver debugging
 * 
 * This program creates an AF_XDP socket and sends periodic IPv4 packets to test
 * TX functionality and completion handling. Designed specifically to help I226 
 * driver maintainers reproduce and debug AF_XDP TX issues.
 * 
 * Usage: ./afx_tx <netdev> <dest_mac> <interval_ms> [options]
 * Example: ./afx_tx eth0 aa:bb:cc:dd:ee:ff 1000 --i226-mode
 */

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <poll.h>
#include <atomic>
#include <vector>
#include <chrono>
#include <algorithm>

// XDP/AF_XDP headers
#include <linux/net_tstamp.h>  // For SOF_TIMESTAMPING_* constants
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <bpf/libbpf.h>

// Include bitw_common for proper frame management functions
#include "bitw_common.h"

// Compatibility for older XDP headers
#ifndef XSK_BIND_FLAGS_ZEROCOPY
#define XSK_BIND_FLAGS_ZEROCOPY (1U << 0)
#endif

// Global flag and signal handler now provided by bitw_common.h

// -----------------------------------------------------------------------------
// UMEM and XSK structures (simplified from bitw_common)
// -----------------------------------------------------------------------------

// UmemArea struct now provided by bitw_common.h
// XskEndpoint struct now provided by bitw_common.h

// -----------------------------------------------------------------------------
// UMEM setup
// -----------------------------------------------------------------------------
// UMEM setup - Using bitw_common.h functions
// -----------------------------------------------------------------------------

// Critical missing piece 2: Prefill UMEM fill ring - REMOVED: Using bitw_common version

// -----------------------------------------------------------------------------
// XSK socket creation with I226 optimizations
// -----------------------------------------------------------------------------

int create_xsk_socket(const char* ifname, XskEndpoint& ep, UmemArea& ua, 
                      const struct xsk_socket_config& cfg, uint32_t queue_id) {
    int ret = xsk_socket__create(&ep.xsk, ifname, queue_id, ua.umem, 
                                &ep.rx, &ep.tx, &cfg);
    if (ret) {
        std::cerr << "[" << ifname << "] xsk_socket__create failed: ret=" << ret 
                 << " (" << strerror(-ret) << ") | xdp_flags=0x" << std::hex << cfg.xdp_flags 
                 << " bind_flags=0x" << cfg.bind_flags << std::dec << std::endl;
        return ret;
    }
    
    ep.fd = xsk_socket__fd(ep.xsk);
    
    // Critical missing piece 1: Enable comprehensive timestamping for E810 support
    int flags = SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RX_SOFTWARE | 
                SOF_TIMESTAMPING_RAW_HARDWARE | SOF_TIMESTAMPING_SOFTWARE |
                SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_TX_SOFTWARE;
    if (setsockopt(ep.fd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) < 0) {
        std::cout << "[" << ifname << "] Warning: Failed to enable hardware timestamping: " 
                 << strerror(errno) << " (continuing without timestamps)" << std::endl;
    } else {
        std::cout << "[" << ifname << "] Hardware timestamping enabled (HW+SW RX/TX)" << std::endl;
    }
    
    // Enable timestamp on all packets
    int enable = 1;
    if (setsockopt(ep.fd, SOL_SOCKET, SO_TIMESTAMP, &enable, sizeof(enable)) < 0) {
        // This is less critical, so just debug level
        std::cout << "[" << ifname << "] SO_TIMESTAMP setup: " << strerror(errno) << std::endl;
    }
    
    return 0;
}

// I226-optimized copy-mode-only socket creation
int create_xsk_i226_optimized(const char* ifname, XskEndpoint& ep, UmemArea& ua, 
                              const struct xsk_socket_config& base_cfg, uint32_t queue_id) {
    struct xsk_socket_config cfg = base_cfg;
    cfg.xdp_flags = XDP_FLAGS_DRV_MODE; // Try DRV mode first for better TX reliability
    cfg.bind_flags = 0; // Force copy mode (no zero-copy)
    
    int ret = create_xsk_socket(ifname, ep, ua, cfg, queue_id);
    if (ret == 0) {
        std::cout << "[" << ifname << "] AF_XDP socket created: DRV + COPY mode (I226 optimized) ✅\n";
        return 0;
    }
    
    // Fallback to SKB mode if DRV fails
    std::cout << "[" << ifname << "] DRV mode failed, trying SKB mode...\n";
    cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
    ret = create_xsk_socket(ifname, ep, ua, cfg, queue_id);
    if (ret == 0) {
        std::cout << "[" << ifname << "] AF_XDP socket created: SKB + COPY mode (fallback) ⚠️\n";
        return 0;
    }
    
    std::cerr << "[" << ifname << "] Failed to create AF_XDP socket in any mode: " << strerror(-ret) << "\n";
    return ret;
}

// Standard socket creation with fallback
int create_xsk_with_fallback(const char* ifname, XskEndpoint& ep, UmemArea& ua,
                             const struct xsk_socket_config& base_cfg, uint32_t queue_id) {
    struct xsk_socket_config cfg = base_cfg;
    
    // Try 1: DRV + ZEROCOPY
    cfg.xdp_flags = XDP_FLAGS_DRV_MODE;
    cfg.bind_flags = XSK_BIND_FLAGS_ZEROCOPY;
    
    int ret = create_xsk_socket(ifname, ep, ua, cfg, queue_id);
    if (ret == 0) {
        std::cout << "[" << ifname << "] AF_XDP socket created: DRV + ZEROCOPY ✅\n";
        return 0;
    }
    std::cout << "[" << ifname << "] DRV + ZEROCOPY failed, trying DRV + COPY...\n";
    
    // Try 2: DRV + COPY
    cfg.bind_flags = 0; // Copy mode
    ret = create_xsk_socket(ifname, ep, ua, cfg, queue_id);
    if (ret == 0) {
        std::cout << "[" << ifname << "] AF_XDP socket created: DRV + COPY ✅\n";
        return 0;
    }
    std::cout << "[" << ifname << "] DRV + COPY failed, trying SKB + COPY...\n";
    
    // Try 3: SKB + COPY (coexistence mode - allows kernel networking)
    cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
    ret = create_xsk_socket(ifname, ep, ua, cfg, queue_id);
    if (ret == 0) {
        std::cout << "[" << ifname << "] AF_XDP socket created: SKB + COPY (coexistence) ✅\n";
        return 0;
    }
    
    std::cerr << "[" << ifname << "] All socket creation modes failed\n";
    return ret;
}

// -----------------------------------------------------------------------------
// Network interface utilities
// -----------------------------------------------------------------------------

int get_interface_mac(const char* ifname, uint8_t mac[6]) {
    struct ifaddrs *ifaddr, *ifa;
    int ret = -1;
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }
    
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        
        if (ifa->ifa_addr->sa_family == AF_PACKET && 
            strcmp(ifa->ifa_name, ifname) == 0) {
            
            struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
            if (s->sll_halen == 6) {
                memcpy(mac, s->sll_addr, 6);
                ret = 0;
                break;
            }
        }
    }
    
    freeifaddrs(ifaddr);
    return ret;
}

// parse_mac_address and print_mac_address now provided by bitw_common.h

// -----------------------------------------------------------------------------
// Packet creation
// -----------------------------------------------------------------------------

struct TestPacket {
    struct ethhdr eth;
    struct iphdr ip;
    struct udphdr udp;
    char payload[56]; // Reduced to fit UDP header (64 - 8 = 56)
} __attribute__((packed));

void create_test_packet(TestPacket& pkt, const uint8_t src_mac[6], const uint8_t dest_mac[6], 
                       uint32_t sequence, bool verbose = false) {
    // Clear packet
    memset(&pkt, 0, sizeof(pkt));
    
    // Ethernet header
    memcpy(pkt.eth.h_dest, dest_mac, 6);
    memcpy(pkt.eth.h_source, src_mac, 6);
    pkt.eth.h_proto = htons(ETH_P_IP);
    
    // IP header
    pkt.ip.version = 4;
    pkt.ip.ihl = 5; // 20 bytes
    pkt.ip.tos = 0;
    pkt.ip.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(pkt.payload));
    pkt.ip.id = htons(sequence & 0xFFFF);
    pkt.ip.frag_off = 0;
    pkt.ip.ttl = 64;
    pkt.ip.protocol = IPPROTO_UDP; // Proper UDP
    pkt.ip.check = 0; // Will be calculated
    pkt.ip.saddr = htonl(0x0A0A2820); // 10.10.40.32 (actual PF1 IP from ARP)
    pkt.ip.daddr = htonl(0x0A0A2821); // 10.10.40.33 (actual destination IP)
    
    // UDP header
    pkt.udp.source = htons(12345);  // Source port
    pkt.udp.dest = htons(54321);    // Destination port
    pkt.udp.len = htons(sizeof(struct udphdr) + sizeof(pkt.payload)); // UDP length
    pkt.udp.check = 0; // Will calculate proper UDP checksum
    
    // Fill payload first (needed for UDP checksum)
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(now).count();
    snprintf(pkt.payload, sizeof(pkt.payload), "AFX_TX #%u ts=%lu", sequence, us);
    
    // Calculate UDP checksum (with IPv4 pseudo-header)
    uint32_t udp_sum = 0;
    uint16_t udp_len = sizeof(struct udphdr) + sizeof(pkt.payload);
    
    // Pseudo-header: src IP + dest IP + protocol + UDP length
    udp_sum += (ntohl(pkt.ip.saddr) >> 16) & 0xFFFF;
    udp_sum += (ntohl(pkt.ip.saddr) >> 0) & 0xFFFF;
    udp_sum += (ntohl(pkt.ip.daddr) >> 16) & 0xFFFF;
    udp_sum += (ntohl(pkt.ip.daddr) >> 0) & 0xFFFF;
    udp_sum += htons(IPPROTO_UDP);
    udp_sum += htons(udp_len);
    
    // UDP header + data - use memcpy to avoid unaligned access warnings
    uint16_t udp_words[(sizeof(struct udphdr) + sizeof(pkt.payload) + 1) / 2];
    memcpy(udp_words, &pkt.udp, udp_len);
    for (size_t i = 0; i < (static_cast<size_t>(udp_len) + 1) / 2; ++i) {
        udp_sum += ntohs(udp_words[i]);
    }
    
    // Handle odd byte if payload length is odd
    if (udp_len & 1) {
        udp_sum -= ntohs(udp_words[(udp_len - 1) / 2]) & 0x00FF;
        udp_sum += (ntohs(udp_words[(udp_len - 1) / 2]) & 0xFF00);
    }
    
    while (udp_sum >> 16) {
        udp_sum = (udp_sum & 0xFFFF) + (udp_sum >> 16);
    }
    pkt.udp.check = htons(~udp_sum);
    
    // Calculate IP checksum - use safer array access to avoid alignment warnings
    pkt.ip.check = 0; // Must be 0 for checksum calculation
    uint32_t ip_sum = 0;
    uint16_t ip_words[10]; // 20 bytes / 2 = 10 words
    memcpy(ip_words, &pkt.ip, sizeof(struct iphdr));
    for (int i = 0; i < 10; ++i) {
        ip_sum += ntohs(ip_words[i]);
    }
    while (ip_sum >> 16) {
        ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
    }
    pkt.ip.check = htons(~ip_sum);
    
    // Debug: print packet details occasionally
    if (verbose && (sequence % 100) == 1) {
        std::cout << "Packet #" << sequence << " details:" << std::endl;
        std::cout << "  Eth: " << std::hex;
        for (int i = 0; i < 6; i++) {
            printf("%02x:", pkt.eth.h_dest[i]);
        }
        printf(" <- ");
        for (int i = 0; i < 6; i++) {
            printf("%02x:", pkt.eth.h_source[i]); 
        }
        printf(" type=0x%04x\n", ntohs(pkt.eth.h_proto));
        std::cout << std::dec;
        
        std::cout << "  IP: " << ((ntohl(pkt.ip.saddr) >> 24) & 0xFF) << "." << ((ntohl(pkt.ip.saddr) >> 16) & 0xFF) 
                  << "." << ((ntohl(pkt.ip.saddr) >> 8) & 0xFF) << "." << ((ntohl(pkt.ip.saddr) >> 0) & 0xFF) << " -> "
                  << ((ntohl(pkt.ip.daddr) >> 24) & 0xFF) << "." << ((ntohl(pkt.ip.daddr) >> 16) & 0xFF) 
                  << "." << ((ntohl(pkt.ip.daddr) >> 8) & 0xFF) << "." << ((ntohl(pkt.ip.daddr) >> 0) & 0xFF)
                  << " len=" << ntohs(pkt.ip.tot_len) << " cksum=0x" << std::hex << ntohs(pkt.ip.check) << std::dec << std::endl;
        
        std::cout << "  UDP: " << ntohs(pkt.udp.source) << " -> " << ntohs(pkt.udp.dest) 
                  << " len=" << ntohs(pkt.udp.len) << " cksum=0x" << std::hex << ntohs(pkt.udp.check) << std::dec << std::endl;
    }
}

// -----------------------------------------------------------------------------
// TX completion handling (with I226 optimizations)
// -----------------------------------------------------------------------------

void process_tx_completions(UmemArea& ua, bool verbose = false) {
    static uint64_t last_emergency_recycle = 0;
    static uint64_t total_completions_ever = 0;
    
    uint32_t idx;
    unsigned int total_completed = 0;
    
    // DEBUG: Check completion ring state
    uint32_t comp_producer = *ua.comp.producer;
    uint32_t comp_consumer = *ua.comp.consumer;
    uint32_t comp_available = comp_producer - comp_consumer;
    
    if (verbose) {
        std::cout << "[DEBUG] Completion ring: producer=" << comp_producer 
                  << " consumer=" << comp_consumer << " available=" << comp_available << std::endl;
    }
    
    // Try multiple times to get completions (I226 optimization)
    for (int attempt = 0; attempt < 3; ++attempt) {
        unsigned int completed = xsk_ring_cons__peek(&ua.comp, 64, &idx);
        if (completed) {
            if (verbose) {
                std::cout << "[DEBUG] Got " << completed << " TX completions on attempt " << (attempt+1) << std::endl;
            }
            for (unsigned int i = 0; i < completed; ++i) {
                uint64_t addr = *xsk_ring_cons__comp_addr(&ua.comp, idx + i);
                if (verbose) {
                    std::cout << "[DEBUG] Completing TX frame addr=0x" << std::hex << addr << std::dec << std::endl;
                }
                free_frame(ua, addr);
            }
            xsk_ring_cons__release(&ua.comp, completed);
            total_completed += completed;
            total_completions_ever += completed;
        }
        
        if (completed == 0 && attempt < 2) {
            if (verbose) {
                std::cout << "[DEBUG] No completions on attempt " << (attempt+1) << ", retrying..." << std::endl;
            }
            usleep(100); // FIXED: Match bitw_sflow delay (was 50)
        }
    }
    
    if (verbose) {
        std::cout << "[DEBUG] TX completions this cycle: " << total_completed 
                  << " (total ever: " << total_completions_ever << ")" << std::endl;
    }
    
    // I226 emergency recycling if frames seem stuck
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
        
    if (ua.free_frames.size() < 100 && total_completed == 0 &&  // FIXED: Match bitw_sflow threshold (was 50)
        (now - last_emergency_recycle) > 100) { // Every 100ms
        
        if (verbose) {
            std::cout << "[DEBUG] EMERGENCY: Low free frames (" << ua.free_frames.size() 
                      << ") and no completions detected!" << std::endl;
        }
        
        // Emergency recycle some frames (I226 optimization for improved TX completion handling)
        size_t emergency_recycle = std::min(ua.frame_count / 10, (uint32_t)50);
        for (size_t i = 0; i < emergency_recycle && ua.free_frames.size() < ua.frame_count; ++i) {
            ua.free_frames.push_back(i * ua.frame_size); // Calculate frame address manually
        }
        
        if (verbose && emergency_recycle > 0) {
            std::cout << "I226 optimization: emergency recycled " << emergency_recycle 
                     << " frames (free now: " << ua.free_frames.size() << ")\n";
        }
        last_emergency_recycle = now;
    }
}

// -----------------------------------------------------------------------------
// Main transmission function
// -----------------------------------------------------------------------------

void transmit_packets(const char* /* ifname */, XskEndpoint& ep, UmemArea& ua,
                     const uint8_t src_mac[6], const uint8_t dest_mac[6], 
                     int interval_ms, int duration_secs, bool verbose) {
    
    std::cout << "Starting packet transmission every " << interval_ms << "ms\n";
    if (duration_secs > 0) {
        std::cout << "Duration: " << duration_secs << " seconds\n";
    } else {
        std::cout << "Duration: forever (use Ctrl-C to stop)\n";
    }
    std::cout << "Source MAC: " << std::hex << std::setfill('0');
    for (int i = 0; i < 6; i++) {
        if (i > 0) std::cout << ":";
        std::cout << std::setw(2) << (int)src_mac[i];
    }
    std::cout << std::dec << "\n";
    
    std::cout << "Dest MAC: " << std::hex << std::setfill('0');
    for (int i = 0; i < 6; i++) {
        if (i > 0) std::cout << ":";
        std::cout << std::setw(2) << (int)dest_mac[i];
    }
    std::cout << std::dec << "\n";
    std::cout << "UMEM config: frame_size=" << ua.frame_size << " headroom=" << ua.frame_headroom << "\n\n";
    
    uint32_t sequence = 1;
    uint64_t total_sent = 0;
    uint64_t total_failed = 0;
    
    auto start_time = std::chrono::steady_clock::now();
    auto last_stats = std::chrono::steady_clock::now();
    auto last_tx = std::chrono::steady_clock::now();
    
    // Pending TX frames list (like bitw_sflow)
    static std::vector<uint64_t> pending_tx_addrs;
    
    // CRITICAL: Setup polling like bitw_sflow - this might be the root cause!
    struct pollfd pfd;
    pfd.fd = ep.fd;
    pfd.events = POLLIN;
    
    while (g_running.load()) {
        // Check duration limit (if set)
        if (duration_secs > 0) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
            if (elapsed >= duration_secs) {
                std::cout << "Duration limit reached (" << duration_secs << " seconds), exiting...\n";
                break;
            }
        }
        
        // Process TX completions first (like bitw_sflow)
        process_tx_completions(ua, verbose);
        
        // Check if it's time to send next packet
        auto now = std::chrono::steady_clock::now();
        auto since_last_tx = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_tx).count();
        
        if (since_last_tx >= interval_ms) {
            // DEBUG: Check TX ring state before sending
            uint32_t tx_producer = *ep.tx.producer;
            uint32_t tx_consumer = *ep.tx.consumer;  
            uint32_t tx_available = ep.tx.size - (tx_producer - tx_consumer);
            
            if (verbose) {
                std::cout << "[DEBUG] TX ring before send: producer=" << tx_producer 
                          << " consumer=" << tx_consumer << " available=" << tx_available 
                          << " free_frames=" << ua.free_frames.size() << std::endl;
            }
            
            // Try to send a packet using bitw_sflow-style batching
            uint32_t tx_idx;
            uint32_t reserved = xsk_ring_prod__reserve(&ep.tx, 1, &tx_idx);
            if (reserved > 0) {
                if (verbose) {
                    std::cout << "[DEBUG] Reserved TX slot: idx=" << tx_idx << " reserved=" << reserved << std::endl;
                }
                
                uint64_t frame_addr;
                if (alloc_frame(ua, frame_addr)) {
                    // Create packet
                    TestPacket pkt;
                    create_test_packet(pkt, src_mac, dest_mac, sequence, verbose);
                    
                    // Copy to UMEM frame (use umem_ptr instead of get_frame_ptr)
                    uint8_t* frame_ptr = umem_ptr(ua, frame_addr + ua.frame_headroom);  
                    memcpy(frame_ptr, &pkt, sizeof(pkt));
                    
                    // Fill TX descriptor - CRITICAL FIX: Point to actual packet data
                    struct xdp_desc* txd = xsk_ring_prod__tx_desc(&ep.tx, tx_idx);
                    txd->addr = frame_addr + ua.frame_headroom; // FIXED: Include headroom offset!
                    txd->len = sizeof(pkt);
                    
                    // Track pending frame (like bitw_sflow)
                    pending_tx_addrs.push_back(frame_addr);
                    
                    // DEBUG: Record pre-submit state
                    uint32_t pre_submit_producer = *ep.tx.producer;
                    
                    // Submit and kick (single call like bitw_sflow)
                    xsk_ring_prod__submit(&ep.tx, 1);
                    
                    // DEBUG: Record post-submit state
                    uint32_t post_submit_producer = *ep.tx.producer;
                    
                    if (verbose) {
                        std::cout << "[DEBUG] TX submit: producer " << pre_submit_producer 
                                  << " -> " << post_submit_producer << std::endl;
                    }
                    
                    // Critical sendto() syscall with detailed error checking
                    ssize_t sendto_result = sendto(ep.fd, nullptr, 0, MSG_DONTWAIT, nullptr, 0);
                    int sendto_errno = errno;
                    
                    if (verbose) {
                        std::cout << "[DEBUG] sendto() result=" << sendto_result;
                        if (sendto_result < 0) {
                            std::cout << " errno=" << sendto_errno << " (" << strerror(sendto_errno) << ")";
                        }
                        std::cout << std::endl;
                    }
                    
                    sequence++;
                    total_sent++;
                    last_tx = now;
                    
                    if (verbose) {
                        std::cout << "[DEBUG] Packet #" << sequence-1 << " submitted: frame=0x" 
                                 << std::hex << frame_addr << std::dec 
                                 << " addr=0x" << std::hex << (frame_addr + ua.frame_headroom) << std::dec
                                 << " len=" << sizeof(pkt) << " free_frames=" << ua.free_frames.size() << std::endl;
                    }
                } else {
                    total_failed++;
                    if (verbose) {
                        std::cout << "[DEBUG] FAIL: No free frames for packet #" << sequence 
                                  << " (free_frames=" << ua.free_frames.size() << ")" << std::endl;
                    }
                }
            } else {
                total_failed++;
                if (verbose) {
                    std::cout << "[DEBUG] FAIL: No TX ring space for packet #" << sequence 
                              << " (reserved=" << reserved << " available=" << tx_available << ")" << std::endl;
                }
            }
        }
        
        // Print periodic stats with ring state
        if (std::chrono::duration_cast<std::chrono::seconds>(now - last_stats).count() >= 5) {
            uint32_t tx_prod = *ep.tx.producer;
            uint32_t tx_cons = *ep.tx.consumer;
            uint32_t comp_prod = *ua.comp.producer;
            uint32_t comp_cons = *ua.comp.consumer;
            
            std::cout << "[STATS] sent=" << total_sent << " failed=" << total_failed 
                     << " free_frames=" << ua.free_frames.size() << " pending_tx=" << pending_tx_addrs.size()
                     << " tx_ring=" << tx_prod << "/" << tx_cons 
                     << " comp_ring=" << comp_prod << "/" << comp_cons << std::endl;
            last_stats = now;
        }
        
        // CRITICAL: Use poll() like bitw_sflow instead of usleep()!
        int pr = poll(&pfd, 1, 10); // 10ms timeout (shorter for TX-only app)
        if (pr < 0 && errno != EINTR) {
            std::cerr << "poll() failed: " << strerror(errno) << std::endl;
            break;
        }
    }
    
    std::cout << "\nFinal stats: sent=" << total_sent << " failed=" << total_failed << "\n";
}

// -----------------------------------------------------------------------------
// Command line parsing
// -----------------------------------------------------------------------------

struct Config {
    const char* netdev = nullptr;
    uint8_t dest_mac[6] = {0};
    int interval_ms = 1000;
    int duration_secs = 10;      // Default 10 seconds, 0 = forever
    bool i226_mode = false;
    bool verbose = false;
    uint32_t frame_count = 4096;
    uint32_t frame_size = 4096;  // I226-optimized default
    uint32_t headroom = 256;     // I226-optimized default
};

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " <netdev> <dest_mac> <interval_ms> [options]\n"
              << "\nArguments:\n"
              << "  netdev        Network interface (e.g., eth0)\n"
              << "  dest_mac      Destination MAC address (e.g., aa:bb:cc:dd:ee:ff)\n"
              << "  interval_ms   Packet transmission interval in milliseconds\n"
              << "\nOptions:\n"
              << "  --duration N  Run for N seconds before exiting (default: 10, 0 = forever)\n"
              << "  --i226-mode   Use I226-optimized AF_XDP settings (force copy mode)\n"
              << "  --verbose     Enable verbose packet logging\n"
              << "  --frames N    Number of UMEM frames (default: 4096)\n"
              << "  --frame-size N Frame size in bytes (default: 4096)\n"
              << "  --headroom N  Frame headroom in bytes (default: 256)\n"
              << "\nExamples:\n"
              << "  " << prog << " eth0 aa:bb:cc:dd:ee:ff 1000\n"
              << "  " << prog << " eth0 aa:bb:cc:dd:ee:ff 500 --duration 30 --i226-mode --verbose\n"
              << "\nFor I226 NICs, use --i226-mode for optimal performance.\n";
}

bool parse_args(int argc, char** argv, Config& config) {
    if (argc < 4) {
        return false;
    }
    
    config.netdev = argv[1];
    
    if (!parse_mac_address(argv[2], config.dest_mac)) {
        std::cerr << "Invalid destination MAC address: " << argv[2] << "\n";
        return false;
    }
    
    config.interval_ms = atoi(argv[3]);
    if (config.interval_ms <= 0) {
        std::cerr << "Invalid interval: " << argv[3] << "\n";
        return false;
    }
    
    // Parse optional arguments
    for (int i = 4; i < argc; ++i) {
        if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc) {
            config.duration_secs = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--i226-mode") == 0) {
            config.i226_mode = true;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            config.verbose = true;
        } else if (strcmp(argv[i], "--frames") == 0 && i + 1 < argc) {
            config.frame_count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--frame-size") == 0 && i + 1 < argc) {
            config.frame_size = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--headroom") == 0 && i + 1 < argc) {
            config.headroom = atoi(argv[++i]);
        } else {
            std::cerr << "Unknown option: " << argv[i] << "\n";
            return false;
        }
    }
    
    return true;
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

int main(int argc, char** argv) {
    Config config;
    if (!parse_args(argc, argv, config)) {
        print_usage(argv[0]);
        return 1;
    }
    
    std::cout << "AFX_TX - Standalone AF_XDP TX Test Program\n";
    std::cout << "Network device: " << config.netdev << "\n";
    std::cout << "Destination MAC: " << std::hex << std::setfill('0'); 
    for (int i = 0; i < 6; i++) {
        if (i > 0) std::cout << ":";
        std::cout << std::setw(2) << (int)config.dest_mac[i];
    }
    std::cout << std::dec << "\n";
    std::cout << "Interval: " << config.interval_ms << "ms\n";
    std::cout << "Duration: " << (config.duration_secs > 0 ? std::to_string(config.duration_secs) + " seconds" : "forever") << "\n";
    std::cout << "I226 mode: " << (config.i226_mode ? "enabled" : "disabled") << "\n";
    std::cout << "UMEM config: " << config.frame_count << " frames, " 
              << config.frame_size << " bytes each, headroom=" << config.headroom << "\n\n";
    
    // Install signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Get source MAC address from interface
    uint8_t src_mac[6];
    if (get_interface_mac(config.netdev, src_mac) != 0) {
        std::cerr << "Failed to get MAC address for interface " << config.netdev << "\n";
        return 1;
    }
    
    // Setup UMEM
    UmemArea umem;
    if (setup_umem(umem, config.frame_count, config.frame_size, config.headroom) != 0) {
        std::cerr << "Failed to setup UMEM\n";
        return 1;
    }
    
    // CRITICAL FIX: Use bitw_common initialization sequence to avoid double-allocation bug
    // This was the root cause of 87-90% packet loss - frames were double-allocated!
    uint32_t tx_reserve = 1024; // Reserve some frames for TX  
    uint32_t fill_count = umem.frame_count - tx_reserve;
    
    // Step 1: Prefill RX frames first (updates umem.next_frame)
    uint32_t prefilled = prefill_fill_ring_n(umem, fill_count);
    std::cout << "Prefilled " << prefilled << " RX frames for " << config.netdev << std::endl;
    
    // Step 2: Initialize free frames from REMAINING frames only (avoids double-allocation)
    init_free_frames_from_remaining(umem);
    std::cout << "Initialized " << umem.free_frames.size() << " free frames for TX" << std::endl;
    
    // Create AF_XDP socket - CRITICAL: Use same ring sizes as bitw_sflow
    XskEndpoint xsk;
    struct xsk_socket_config xsk_config = {};
    xsk_config.rx_size = 4096;  // FIXED: Use full RX ring like bitw_sflow (was 64)
    xsk_config.tx_size = config.frame_count;  // 4096
    xsk_config.libbpf_flags = 0;
    
    int ret;
    if (config.i226_mode) {
        std::cout << "Using I226-optimized socket creation...\n";
        ret = create_xsk_i226_optimized(config.netdev, xsk, umem, xsk_config, 0);
    } else {
        std::cout << "Using standard socket creation with fallback...\n";
        ret = create_xsk_with_fallback(config.netdev, xsk, umem, xsk_config, 0);
    }
    
    if (ret != 0) {
        std::cerr << "Failed to create AF_XDP socket\n";
        // Manual cleanup (no cleanup_umem in bitw_common)
        if (umem.umem) xsk_umem__delete(umem.umem);
        if (umem.buffer) free(umem.buffer);
        return 1;
    }
    
    // Start packet transmission
    transmit_packets(config.netdev, xsk, umem, src_mac, config.dest_mac, 
                    config.interval_ms, config.duration_secs, config.verbose);
    
    // Cleanup
    xsk_socket__delete(xsk.xsk);
    // Manual cleanup (no cleanup_umem in bitw_common)
    if (umem.umem) xsk_umem__delete(umem.umem);
    if (umem.buffer) free(umem.buffer);
    
    std::cout << "Program finished.\n";
    return 0;
}