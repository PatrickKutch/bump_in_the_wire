// bump_mt_pin.cpp
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

static const char* log_level_str(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

static std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S")
       << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    return ss.str();
}

#define LOG(level, ...) do { \
    std::fprintf(stderr, "[%s] [%s] ", get_timestamp().c_str(), log_level_str(level)); \
    std::fprintf(stderr, __VA_ARGS__); \
    std::fprintf(stderr, "\n"); \
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

// -----------------------------------------------------------------------------
// Helpers: UMEM address & free-list
// -----------------------------------------------------------------------------
static inline uint8_t* umem_ptr(UmemArea& ua, uint64_t addr) {
    // addr is an offset into UMEM (often frame_index * frame_size)
    return reinterpret_cast<uint8_t*>(ua.buffer) + (addr % ua.size);
}

static inline void init_free_frames_from_remaining(UmemArea& ua) {
    // Use frames not already handed to fill ring (next_frame..frame_count-1)
    ua.free_frames.clear();
    for (uint32_t i = static_cast<uint32_t>(ua.next_frame); i < ua.frame_count; ++i) {
        ua.free_frames.push_back(static_cast<uint64_t>(i) * ua.frame_size);
    }
}

static inline bool alloc_frame(UmemArea& ua, uint64_t& addr_out) {
    if (ua.free_frames.empty()) return false;
    addr_out = ua.free_frames.back();
    ua.free_frames.pop_back();
    return true;
}

static inline void free_frame(UmemArea& ua, uint64_t addr) {
    ua.free_frames.push_back(addr);
}

// -----------------------------------------------------------------------------
// EtherType parsing (VLAN aware) for debug
// -----------------------------------------------------------------------------
static inline bool read_be16(const uint8_t* p, uint16_t& out) {
    uint16_t tmp;
    std::memcpy(&tmp, p, sizeof(tmp));
    out = ntohs(tmp);
    return true;
}

static inline const char* ethertype_to_str(uint16_t et) {
    switch (et) {
        case 0x0800: return "IPv4";
        case 0x86DD: return "IPv6";
        case 0x0806: return "ARP";
        case 0x8100: return "802.1Q (VLAN tag)";
        case 0x88A8: return "802.1ad (QinQ)";
        case 0x8847: return "MPLS unicast";
        case 0x8848: return "MPLS multicast";
        default:     return "unknown";
    }
}

// Walk one or two VLAN tags and return the encapsulated EtherType
static inline bool parse_ethertype_vlan_aware(const uint8_t* frame, uint32_t len, uint16_t& ether_type_out) {
    if (len < 14) return false; // Ethernet header min
    size_t off = 12;
    uint16_t et = 0;
    if (!read_be16(frame + off, et)) return false;

    int max_tags = 2;
    while ((et == 0x8100 || et == 0x88A8 || et == 0x9100) && max_tags-- > 0) {
        if (len < off + 4 + 2) return false; // ensure space for VLAN + next EtherType
        off += 4; // skip TCI
        if (!read_be16(frame + off, et)) return false;
    }

    ether_type_out = et;
    return true;
}

// -----------------------------------------------------------------------------
// Hardware timestamp extraction
// -----------------------------------------------------------------------------
// Try to get PTP hardware clock timestamp directly
static bool get_ptp_hw_timestamp(uint64_t& timestamp_ns) {
    static int ptp_fd = -1;
    static bool ptp_init_attempted = false;
    
    // Initialize PTP clock file descriptor once
    if (!ptp_init_attempted) {
        ptp_init_attempted = true;
        ptp_fd = open("/dev/ptp0", O_RDONLY);
        if (ptp_fd < 0) {
            LOG(LogLevel::DEBUG, "Failed to open /dev/ptp0: %s", strerror(errno));
            return false;
        }
        LOG(LogLevel::INFO, "PTP hardware clock /dev/ptp0 opened successfully");
    }
    
    if (ptp_fd < 0) return false;
    
    struct ptp_sys_offset_precise pso = {};
    if (ioctl(ptp_fd, PTP_SYS_OFFSET_PRECISE, &pso) == 0) {
        // Use PTP hardware timestamp
        timestamp_ns = (uint64_t)pso.device.sec * 1000000000ULL + (uint64_t)pso.device.nsec;
        return true;
    }
    
    // Fallback to basic PTP clock read
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
        return true;
    }
    
    return false;
}

static bool extract_hw_timestamp(int sockfd, uint64_t& timestamp_ns) {
    // Try to get hardware timestamp from socket error queue
    char control[256];
    char data[1];
    struct iovec iov = { data, sizeof(data) };
    struct msghdr msg = {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    
    // Check for available timestamp on error queue (non-blocking)
    ssize_t ret = recvmsg(sockfd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
    if (ret < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            // Only log if it's not just "no data available"
            LOG(LogLevel::DEBUG, "recvmsg MSG_ERRQUEUE failed: %s", strerror(errno));
        }
        return false;
    }
    
    // Parse control messages for timestamp
    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET) {
            if (cmsg->cmsg_type == SCM_TIMESTAMPING) {
                // Extract hardware timestamp from control message
                struct timespec* ts = (struct timespec*)CMSG_DATA(cmsg);
                // ts[0] = software timestamp, ts[1] = deprecated, ts[2] = hardware timestamp
                if (ts[2].tv_sec != 0 || ts[2].tv_nsec != 0) {
                    timestamp_ns = (uint64_t)ts[2].tv_sec * 1000000000ULL + (uint64_t)ts[2].tv_nsec;
                    return true;
                }
                // Fallback to software timestamp if hardware not available
                if (ts[0].tv_sec != 0 || ts[0].tv_nsec != 0) {
                    timestamp_ns = (uint64_t)ts[0].tv_sec * 1000000000ULL + (uint64_t)ts[0].tv_nsec;
                    return true;
                }
            } else if (cmsg->cmsg_type == SCM_TIMESTAMPNS) {
                // Alternative nanosecond timestamp
                struct timespec* ts = (struct timespec*)CMSG_DATA(cmsg);
                timestamp_ns = (uint64_t)ts->tv_sec * 1000000000ULL + (uint64_t)ts->tv_nsec;
                return true;
            }
        }
    }
    
    return false;
}

// -----------------------------------------------------------------------------
// S-Flow sampling configuration
// -----------------------------------------------------------------------------
struct SFlowConfig {
    uint32_t sampling_rate = 0;  // 0 = disabled, N = sample 1 out of N packets
    std::vector<uint16_t> ethertypes;
    bool skip_vlan = true;       // true = skip VLAN tags to find EtherType
    
    bool is_enabled() const { return sampling_rate > 0 && !ethertypes.empty(); }
};

static bool parse_ethertypes(const char* str, std::vector<uint16_t>& ethertypes) {
    ethertypes.clear();
    if (!str || !*str) return false;
    
    std::string input(str);
    size_t pos = 0;
    
    while (pos < input.length()) {
        size_t comma = input.find(',', pos);
        std::string token = input.substr(pos, comma - pos);
        
        // Remove whitespace
        token.erase(0, token.find_first_not_of(" \t"));
        token.erase(token.find_last_not_of(" \t") + 1);
        
        if (token.empty()) {
            pos = (comma == std::string::npos) ? input.length() : comma + 1;
            continue;
        }
        
        // Parse hex value (with or without 0x prefix)
        char* endptr;
        unsigned long val = strtoul(token.c_str(), &endptr, 16);
        if (*endptr != '\0' || val > 0xFFFF) {
            std::cerr << "Invalid EtherType: " << token << "\n";
            return false;
        }
        
        ethertypes.push_back(static_cast<uint16_t>(val));
        pos = (comma == std::string::npos) ? input.length() : comma + 1;
    }
    
    return !ethertypes.empty();
}

// Get EtherType with optional VLAN skipping
static inline bool get_ethertype(const uint8_t* frame, uint32_t len, uint16_t& ether_type_out, bool skip_vlan) {
    if (skip_vlan) {
        return parse_ethertype_vlan_aware(frame, len, ether_type_out);
    } else {
        // Direct EtherType read without VLAN skipping
        if (len < 14) return false;
        return read_be16(frame + 12, ether_type_out);
    }
}

// -----------------------------------------------------------------------------
// S-Flow sampling state (per direction)
// -----------------------------------------------------------------------------
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
    // You can modify this logic to conditionally return a packet or nullptr
    LOG(LogLevel::INFO, "[%s SFLOW] Creating packet copy for transmission", tag);
    return std::make_unique<SFlowPacket>(frame, len, timestamp_ns, has_timestamp);
}

// -----------------------------------------------------------------------------
// Helpers: UMEM and Socket Setup
// -----------------------------------------------------------------------------
int setup_umem(UmemArea& ua,
               uint32_t frame_count,
               uint32_t frame_size = 2048,
               uint32_t frame_headroom = 0,
               uint32_t fill_size = 4096,
               uint32_t comp_size = 4096)
{
    ua.frame_count = frame_count;
    ua.frame_size  = frame_size;
    ua.frame_headroom = frame_headroom;
    ua.size = static_cast<uint64_t>(frame_count) * frame_size;

    const size_t align = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    int ret = posix_memalign(&ua.buffer, align, ua.size);
    if (ret != 0 || !ua.buffer) {
        std::cerr << "posix_memalign failed: " << ret << "\n";
        return 1;
    }
    std::memset(ua.buffer, 0, ua.size);

    struct xsk_umem_config ucfg {};
    ucfg.fill_size      = fill_size;
    ucfg.comp_size      = comp_size;
    ucfg.frame_size     = frame_size;
    ucfg.frame_headroom = frame_headroom;
    ucfg.flags          = 0;

    ret = xsk_umem__create(&ua.umem, ua.buffer, ua.size, &ua.fill, &ua.comp, &ucfg);
    if (ret) {
        std::cerr << "xsk_umem__create failed: " << ret << "\n";
        free(ua.buffer);
        ua.buffer = nullptr;
        return 1;
    }
    return 0;
}

int setup_rings(const char* ifname,
                uint32_t queue_id,
                UmemArea& ua,
                struct xsk_socket_config& cfg,
                XskEndpoint& ep)
{
    int ret = xsk_socket__create(&ep.xsk, ifname, queue_id, ua.umem, &ep.rx, &ep.tx, &cfg);
    if (ret) {
        LOG(LogLevel::ERROR, "[%s] xsk_socket__create failed: ret=%d (%s) | xdp_flags=0x%x bind_flags=0x%x",
            ifname, ret, strerror(-ret), cfg.xdp_flags, cfg.bind_flags);
        return 1;
    }
    ep.fd = xsk_socket__fd(ep.xsk);
    
    // Enable comprehensive timestamping for 1588 PTP support
    int flags = SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RX_SOFTWARE | 
                SOF_TIMESTAMPING_RAW_HARDWARE | SOF_TIMESTAMPING_SOFTWARE |
                SOF_TIMESTAMPING_TX_HARDWARE | SOF_TIMESTAMPING_TX_SOFTWARE;
    if (setsockopt(ep.fd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags)) < 0) {
        LOG(LogLevel::WARN, "[%s] Failed to enable hardware timestamping: %s (continuing without timestamps)",
            ifname, strerror(errno));
    } else {
        LOG(LogLevel::INFO, "[%s] Hardware timestamping enabled (HW+SW RX/TX)", ifname);
    }
    
    // Enable timestamp on all packets
    int enable = 1;
    if (setsockopt(ep.fd, SOL_SOCKET, SO_TIMESTAMP, &enable, sizeof(enable)) < 0) {
        LOG(LogLevel::DEBUG, "[%s] SO_TIMESTAMP failed: %s", ifname, strerror(errno));
    }
    
    return 0;
}

// Prefill up to 'count' frames into the fill ring. Returns number queued.
uint32_t prefill_fill_ring_n(UmemArea& ua, uint32_t count)
{
    const uint32_t want  = std::min(count, ua.frame_count);
    const uint32_t CHUNK = 256;
    uint32_t total = 0;

    while (total < want) {
        uint32_t idx = 0;
        uint32_t to_reserve = std::min(CHUNK, want - total);
        uint32_t space = xsk_ring_prod__reserve(&ua.fill, to_reserve, &idx);
        if (space == 0) break;

        for (uint32_t i = 0; i < space; ++i) {
            uint64_t addr = (ua.next_frame % ua.frame_count) * ua.frame_size;
            *xsk_ring_prod__fill_addr(&ua.fill, idx + i) = addr;
            ua.next_frame++;
        }
        xsk_ring_prod__submit(&ua.fill, space);
        total += space;
    }
    return total;
}

// Simple wrapper (one attempt)
int create_xsk_socket(const char* ifname,
                      XskEndpoint& ep,
                      UmemArea& ua,
                      struct xsk_socket_config& cfg,
                      uint32_t queue_id = 0)
{
    if (setup_rings(ifname, queue_id, ua, cfg, ep)) {
        std::cerr << "Failed to create XSK socket on interface: " << ifname << "\n";
        return 1;
    }
    LOG(LogLevel::INFO, "Created XSK socket on interface: %s (queue %u)", ifname, queue_id);
    return 0;
}

// Try: DRV+ZEROCOPY -> DRV+COPY -> (optional) SKB+COPY
int create_xsk_with_fallback(const char* ifname,
                             XskEndpoint& ep,
                             UmemArea& ua,
                             const struct xsk_socket_config& base_cfg,
                             /*out*/ bool& using_zerocopy,
                             /*out*/ bool& using_skb_mode,
                             uint32_t queue_id = 0,
                             bool allow_skb_fallback = true)
{
    using_zerocopy = false;
    using_skb_mode = false;

    // 1) DRV + ZEROCOPY
    {
        struct xsk_socket_config cfg = base_cfg;
        cfg.xdp_flags  = (base_cfg.xdp_flags & ~XDP_FLAGS_SKB_MODE) | XDP_FLAGS_DRV_MODE;
        cfg.bind_flags = XSK_BIND_FLAGS_ZEROCOPY;
        if (create_xsk_socket(ifname, ep, ua, cfg, queue_id) == 0) {
            LOG(LogLevel::INFO, "[%s] bound: DRV + ZEROCOPY ✅", ifname);
            using_zerocopy = true;
            using_skb_mode = false;
            return 0;
        }
        LOG(LogLevel::WARN, "[%s] DRV + ZEROCOPY bind failed, will try DRV + COPY...", ifname);
    }

    // 2) DRV + COPY (bind_flags=0)
    {
        struct xsk_socket_config cfg = base_cfg;
        cfg.xdp_flags  = (base_cfg.xdp_flags & ~XDP_FLAGS_SKB_MODE) | XDP_FLAGS_DRV_MODE;
        cfg.bind_flags = 0;
        if (create_xsk_socket(ifname, ep, ua, cfg, queue_id) == 0) {
            LOG(LogLevel::INFO, "[%s] bound: DRV + COPY (no zerocopy) ✅", ifname);
            using_zerocopy = false;
            using_skb_mode = false;
            return 0;
        }
        LOG(LogLevel::WARN, "[%s] DRV + COPY bind failed%s", ifname, 
            allow_skb_fallback ? ", will try SKB + COPY..." : "");
    }

    if (!allow_skb_fallback) {
        std::fprintf(stderr, "[%s] no SKB fallback allowed; giving up.\n", ifname);
        return 1;
    }

    // 3) SKB + COPY (bind_flags=0)
    {
        struct xsk_socket_config cfg = base_cfg;
        cfg.xdp_flags  = (base_cfg.xdp_flags & ~XDP_FLAGS_DRV_MODE) | XDP_FLAGS_SKB_MODE;
        cfg.bind_flags = 0;
        if (create_xsk_socket(ifname, ep, ua, cfg, queue_id) == 0) {
            LOG(LogLevel::INFO, "[%s] bound: SKB + COPY (fallback) ✅", ifname);
            using_zerocopy = false;
            using_skb_mode = true;
            return 0;
        }
        LOG(LogLevel::ERROR, "[%s] SKB + COPY bind failed; giving up.", ifname);
    }

    return 1;
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
                        LOG(LogLevel::DEBUG, "[%s] S-Flow packet sent: len=%u (no timestamp)", tag, sflow_pkt->length);
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

static int pin_current_thread_to_cpu(int cpu_id) {
    if (cpu_id < 0) return 0; // no pin requested

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);

    pthread_t tid = pthread_self();
    int ret = pthread_setaffinity_np(tid, sizeof(cpuset), &cpuset);
    if (ret != 0) {
        LOG(LogLevel::ERROR, "pthread_setaffinity_np(cpu=%d) failed: %s", cpu_id, strerror(ret));
        return -1;
    }

    // Verify affinity
    cpu_set_t checkset;
    CPU_ZERO(&checkset);
    if (pthread_getaffinity_np(tid, sizeof(checkset), &checkset) == 0) {
        std::stringstream ss;
        for (int i = 0; i < CPU_SETSIZE; ++i) {
            if (CPU_ISSET(i, &checkset)) ss << i << " ";
        }
        LOG(LogLevel::DEBUG, "Thread affinity confirmed: %s", ss.str().c_str());
    } else {
        LOG(LogLevel::WARN, "Failed to verify thread affinity");
    }

    return 0;
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
            if (skip_str == "true") {
                cmd.sflow.skip_vlan = true;
            } else if (skip_str == "false") {
                cmd.sflow.skip_vlan = false;
            } else {
                std::cerr << "Invalid skip_vlan value: " << skip_str << " (use true/false)\n";
                return false;
            }
        } else {
            std::cerr << "Unknown or incomplete option: " << argv[i] << "\n";
            return false;
        }
    }
    
    // Validate S-Flow config - only validate when sampling is actually enabled
    if (cmd.sflow.sampling_rate > 0 && cmd.sflow.ethertypes.empty()) {
        std::cerr << "S-Flow sampling rate specified but no EtherTypes provided\n";
        return false;
    }
    // Note: Allow ethertypes with sampling_rate=0 since 0 means disabled anyway
    
    return true;
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------
static std::atomic<bool> g_running(true);

static void handle_signal(int) {
    g_running.store(false, std::memory_order_relaxed);
}

int main(int argc, char** argv) {
    Cmd cmd;
    if (!parse_args(argc, argv, cmd)) {
        print_usage(argv[0]);
        return 1;
    }

    const char* devA = cmd.devA;
    const char* devB = cmd.devB;

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

    LOG(LogLevel::INFO, "[summary] %s: %s, %s", devA, A_zerocopy ? "zerocopy" : "copy", A_skb ? "SKB" : "DRV");
    LOG(LogLevel::INFO, "[summary] %s: %s, %s", devB, B_zerocopy ? "zerocopy" : "copy", B_skb ? "SKB" : "DRV");

    // --- Prefill fill rings & build TX freelists ---
    // Fill gets (frame_count - TX_RESERVE) frames; remainder becomes TX freelist.
    uint32_t fillA = prefill_fill_ring_n(umemA, std::max(0u, umemA.frame_count - TX_RESERVE));
    init_free_frames_from_remaining(umemA);
    LOG(LogLevel::INFO, "%s: prefilled %u frames, TX free %zu", devA, fillA, umemA.free_frames.size());

    uint32_t fillB = prefill_fill_ring_n(umemB, std::max(0u, umemB.frame_count - TX_RESERVE));
    init_free_frames_from_remaining(umemB);
    LOG(LogLevel::INFO, "%s: prefilled %u frames, TX free %zu", devB, fillB, umemB.free_frames.size());

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
