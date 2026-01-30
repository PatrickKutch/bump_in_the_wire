#pragma once

#include <iostream>
#include <vector>
#include <memory>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <algorithm>
#include <atomic>
#include <thread>
#include <csignal>
#include <cerrno>

#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>   // sendto
#include <cstdio>         // perror, fprintf
#include <arpa/inet.h>    // ntohs
#include <linux/net_tstamp.h> // timestamping constants
#include <linux/sockios.h>    // socket ioctls
#include <sys/uio.h>          // iovec for recvmsg
#include <linux/errqueue.h>   // sock_extended_err
#include <linux/ptp_clock.h>  // PTP clock interface
#include <sys/ioctl.h>        // ioctl
#include <fcntl.h>            // open, O_RDONLY

#include <pthread.h>
#include <sched.h>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <random>
#include <functional>

#include <xdp/xsk.h>
#include <linux/if_link.h> // XDP_FLAGS_*
#include <linux/if_xdp.h>  // kernel UAPI

// -----------------------------------------------------------------------------
// Compatibility shim for older headers (define zerocopy bind flag if missing)
// -----------------------------------------------------------------------------
#ifndef XSK_BIND_FLAGS_ZEROCOPY
#define XSK_BIND_FLAGS_ZEROCOPY (1u << 0)
#endif

// -----------------------------------------------------------------------------
// Logging utilities for container-friendly output
// -----------------------------------------------------------------------------
enum class LogLevel { DEBUG, INFO, WARN, ERROR };

// Global log level and verbose settings
extern LogLevel g_log_level;
extern bool g_verbose_mode;

const char* log_level_str(LogLevel level);
std::string get_timestamp();
void set_log_level(LogLevel level);
void set_verbose_mode(bool verbose);

#define LOG(level, ...) do { \
    if (level >= g_log_level) { \
        std::fprintf(stderr, "[%s] [%s] ", get_timestamp().c_str(), log_level_str(level)); \
        std::fprintf(stderr, __VA_ARGS__); \
        std::fprintf(stderr, "\n"); \
    } \
} while(0)

// -----------------------------------------------------------------------------
// Simple resource structs
// -----------------------------------------------------------------------------
struct UmemArea {
    void*               buffer = nullptr;   // backing memory
    uint64_t            size = 0;           // total bytes
    uint32_t            frame_size = 2048;  // bytes per frame
    uint32_t            frame_headroom = 0; // bytes before packet
    uint32_t            frame_count = 0;    // number of frames
    uint64_t            next_frame = 0;     // frames handed to fill ring so far

    struct xsk_umem*    umem = nullptr;
    struct xsk_ring_prod fill {};           // UMEM fill ring (user -> kernel)
    struct xsk_ring_cons comp {};           // UMEM completion ring (kernel -> user)

    // Free-list for user-managed TX frames (used when we transmit on this UMEM's socket)
    std::vector<uint64_t> free_frames;
};

struct XskEndpoint {
    struct xsk_socket*  xsk = nullptr;
    struct xsk_ring_cons rx {};             // RX ring (kernel -> user)
    struct xsk_ring_prod tx {};             // TX ring (user -> kernel)
    int                 fd = -1;
};

// Packet parsing result structure
struct PacketLayers {
    const uint8_t* packet_start = nullptr;    // Start of entire packet
    uint32_t packet_len = 0;                  // Total packet length
    
    const uint8_t* eth_header = nullptr;      // Ethernet header
    uint32_t eth_header_len = 0;              // Ethernet + VLAN header length
    
    const uint8_t* ip_header = nullptr;       // IP header (IPv4/IPv6)
    uint32_t ip_header_len = 0;               // IP header length
    uint16_t ip_version = 0;                  // 4 or 6
    
    const uint8_t* l4_header = nullptr;       // L4 header (TCP/UDP/etc)
    uint32_t l4_header_len = 0;               // L4 header length
    uint8_t l4_protocol = 0;                  // Protocol number (6=TCP, 17=UDP)
    
    const uint8_t* l4_payload = nullptr;      // L4 payload data
    uint32_t l4_payload_len = 0;              // L4 payload length
    
    bool valid = false;                       // True if parsing succeeded
};

// S-Flow sampling configuration
struct SFlowConfig {
    uint32_t sampling_rate = 0;  // 0 = disabled, N = sample 1 out of N packets
    std::vector<uint16_t> ethertypes;
    bool skip_vlan = true;       // true = skip VLAN tags to find EtherType
    uint8_t dest_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01}; // Magic destination MAC
    
    bool is_enabled() const { return sampling_rate > 0 && !ethertypes.empty(); }
};

// S-Flow sampling state (per direction)
struct SFlowState {
    uint32_t packet_count = 0;
    uint32_t sampled_count = 0;
};

// Structure to hold S-Flow packet data to be sent
struct SFlowPacket {
    std::vector<uint8_t> data;
    uint32_t length;
    uint64_t timestamp_ns; // 1588 hardware timestamp in nanoseconds
    bool has_timestamp;
    
    SFlowPacket(const uint8_t* frame, uint32_t len, uint64_t ts_ns = 0, bool has_ts = false) 
        : data(frame, frame + len), length(len), timestamp_ns(ts_ns), has_timestamp(has_ts) {}
};

// -----------------------------------------------------------------------------
// Function declarations
// -----------------------------------------------------------------------------

// Helpers: UMEM address & free-list
uint8_t* umem_ptr(UmemArea& ua, uint64_t addr);
void init_free_frames_from_remaining(UmemArea& ua);
bool alloc_frame(UmemArea& ua, uint64_t& addr_out);
void free_frame(UmemArea& ua, uint64_t addr);

// EtherType parsing (VLAN aware) for debug
bool read_be16(const uint8_t* p, uint16_t& out);
const char* ethertype_to_str(uint16_t et);
bool parse_ethertype_vlan_aware(const uint8_t* frame, uint32_t len, uint16_t& ether_type_out);

// Hardware timestamp extraction
bool get_ptp_hw_timestamp(uint64_t& timestamp_ns);
bool extract_hw_timestamp(int sockfd, uint64_t& timestamp_ns);

// S-Flow configuration parsing
bool parse_ethertypes(const char* str, std::vector<uint16_t>& ethertypes);
bool parse_mac_address(const char* str, uint8_t* mac);
bool get_ethertype(const uint8_t* frame, uint32_t len, uint16_t& ether_type_out, bool skip_vlan);

// Packet parsing helper
PacketLayers parse_packet_layers(const uint8_t* packet, uint32_t packet_len, uint8_t target_protocol = 0);

// Helpers: UMEM and Socket Setup
int setup_umem(UmemArea& ua,
               uint32_t frame_count,
               uint32_t frame_size = 2048,
               uint32_t frame_headroom = 0,
               uint32_t fill_size = 4096,
               uint32_t comp_size = 4096);

int setup_rings(const char* ifname,
                uint32_t queue_id,
                UmemArea& ua,
                struct xsk_socket_config& cfg,
                XskEndpoint& ep);

uint32_t prefill_fill_ring_n(UmemArea& ua, uint32_t count);

int create_xsk_socket(const char* ifname,
                      XskEndpoint& ep,
                      UmemArea& ua,
                      struct xsk_socket_config& cfg,
                      uint32_t queue_id = 0);

int create_xsk_with_fallback(const char* ifname,
                             XskEndpoint& ep,
                             UmemArea& ua,
                             const struct xsk_socket_config& base_cfg,
                             /*out*/ bool& using_zerocopy,
                             /*out*/ bool& using_skb_mode,
                             uint32_t queue_id = 0,
                             bool allow_skb_fallback = true);

// CPU pinning
int pin_current_thread_to_cpu(int cpu_id);

// Global running flag
extern std::atomic<bool> g_running;
void handle_signal(int);