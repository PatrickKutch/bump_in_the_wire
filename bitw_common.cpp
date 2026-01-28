#include "bitw_common.h"

// -----------------------------------------------------------------------------
// Logging utilities implementation
// -----------------------------------------------------------------------------
const char* log_level_str(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S")
       << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    return ss.str();
}

// -----------------------------------------------------------------------------
// Helpers: UMEM address & free-list
// -----------------------------------------------------------------------------
uint8_t* umem_ptr(UmemArea& ua, uint64_t addr) {
    // addr is an offset into UMEM (often frame_index * frame_size)
    return reinterpret_cast<uint8_t*>(ua.buffer) + (addr % ua.size);
}

void init_free_frames_from_remaining(UmemArea& ua) {
    // Use frames not already handed to fill ring (next_frame..frame_count-1)
    ua.free_frames.clear();
    for (uint32_t i = static_cast<uint32_t>(ua.next_frame); i < ua.frame_count; ++i) {
        ua.free_frames.push_back(static_cast<uint64_t>(i) * ua.frame_size);
    }
}

bool alloc_frame(UmemArea& ua, uint64_t& addr_out) {
    if (ua.free_frames.empty()) return false;
    addr_out = ua.free_frames.back();
    ua.free_frames.pop_back();
    return true;
}

void free_frame(UmemArea& ua, uint64_t addr) {
    ua.free_frames.push_back(addr);
}

// -----------------------------------------------------------------------------
// EtherType parsing (VLAN aware) for debug
// -----------------------------------------------------------------------------
bool read_be16(const uint8_t* p, uint16_t& out) {
    uint16_t tmp;
    std::memcpy(&tmp, p, sizeof(tmp));
    out = ntohs(tmp);
    return true;
}

const char* ethertype_to_str(uint16_t et) {
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
bool parse_ethertype_vlan_aware(const uint8_t* frame, uint32_t len, uint16_t& ether_type_out) {
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
bool get_ptp_hw_timestamp(uint64_t& timestamp_ns) {
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

bool extract_hw_timestamp(int sockfd, uint64_t& timestamp_ns) {
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
// S-Flow configuration parsing
// -----------------------------------------------------------------------------
bool parse_ethertypes(const char* str, std::vector<uint16_t>& ethertypes) {
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

bool parse_mac_address(const char* str, uint8_t* mac) {
    if (!str || !*str || !mac) return false;
    
    // Parse MAC format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
    int values[6];
    int count = sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x", 
                      &values[0], &values[1], &values[2], 
                      &values[3], &values[4], &values[5]);
    
    if (count != 6) {
        // Try dash format
        count = sscanf(str, "%02x-%02x-%02x-%02x-%02x-%02x", 
                      &values[0], &values[1], &values[2], 
                      &values[3], &values[4], &values[5]);
    }
    
    if (count != 6) {
        std::cerr << "Invalid MAC address format: " << str << " (use XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)\n";
        return false;
    }
    
    // Check range and copy
    for (int i = 0; i < 6; i++) {
        if (values[i] < 0 || values[i] > 255) {
            std::cerr << "Invalid MAC address byte value: " << values[i] << "\n";
            return false;
        }
        mac[i] = static_cast<uint8_t>(values[i]);
    }
    
    return true;
}

// Get EtherType with optional VLAN skipping
bool get_ethertype(const uint8_t* frame, uint32_t len, uint16_t& ether_type_out, bool skip_vlan) {
    if (skip_vlan) {
        return parse_ethertype_vlan_aware(frame, len, ether_type_out);
    } else {
        // Direct EtherType read without VLAN skipping
        if (len < 14) return false;
        return read_be16(frame + 12, ether_type_out);
    }
}

// -----------------------------------------------------------------------------
// Packet parsing helper
// -----------------------------------------------------------------------------
// Parse packet layers and return pointers to headers and payload
PacketLayers parse_packet_layers(const uint8_t* packet, uint32_t packet_len, uint8_t target_protocol) {
    PacketLayers layers = {};
    layers.packet_start = packet;
    layers.packet_len = packet_len;
    
    if (packet_len < 14) {
        LOG(LogLevel::DEBUG, "parse_packet_layers: INVALID - packet too short (%u bytes, need >= 14)", packet_len);
        return layers; // Too short for Ethernet header
    }
    
    // Parse Ethernet header
    layers.eth_header = packet;
    uint32_t eth_offset = 14; // Start after basic Ethernet header
    
    // Handle VLAN tags
    uint16_t ethertype = 0;
    if (!parse_ethertype_vlan_aware(packet, packet_len, ethertype)) {
        LOG(LogLevel::DEBUG, "parse_packet_layers: INVALID - failed to parse EtherType (VLAN-aware)");
        return layers;
    }
    
    // Calculate actual Ethernet + VLAN header length
    const uint8_t* eth_type_ptr = packet + 12;
    uint16_t et;
    read_be16(eth_type_ptr, et);
    while ((et == 0x8100 || et == 0x88A8 || et == 0x9100) && eth_offset + 4 <= packet_len) {
        eth_offset += 4; // Skip VLAN tag
        eth_type_ptr += 4;
        if (eth_offset + 2 <= packet_len) {
            read_be16(eth_type_ptr, et);
        } else {
            break;
        }
    }
    layers.eth_header_len = eth_offset;
    
    // Parse IP header
    if (ethertype == 0x0800 && packet_len >= eth_offset + 20) { // IPv4
        layers.ip_header = packet + eth_offset;
        layers.ip_version = 4;
        
        const uint8_t* ip_hdr = layers.ip_header;
        uint8_t ihl = (ip_hdr[0] & 0x0F) * 4; // IP Header Length
        layers.ip_header_len = ihl;
        layers.l4_protocol = ip_hdr[9]; // Protocol field
        
        if (packet_len >= eth_offset + ihl) {
            layers.l4_header = packet + eth_offset + ihl;
        } else {
            LOG(LogLevel::DEBUG, "parse_packet_layers: INVALID - IPv4 packet too short for IP header (len=%u, need %u)", 
                packet_len, eth_offset + ihl);
            return layers;
        }
    } else if (ethertype == 0x86DD && packet_len >= eth_offset + 40) { // IPv6
        layers.ip_header = packet + eth_offset;
        layers.ip_version = 6;
        layers.ip_header_len = 40; // Fixed IPv6 header size
        
        const uint8_t* ipv6_hdr = layers.ip_header;
        layers.l4_protocol = ipv6_hdr[6]; // Next Header field
        
        if (packet_len >= eth_offset + 40) {
            layers.l4_header = packet + eth_offset + 40;
        } else {
            LOG(LogLevel::DEBUG, "parse_packet_layers: INVALID - IPv6 packet too short for header (len=%u, need %u)", 
                packet_len, eth_offset + 40);
            return layers;
        }
    } else {
        // LOG(LogLevel::DEBUG, "parse_packet_layers: INVALID - unsupported EtherType 0x%04x or insufficient length (len=%u, eth_offset=%u)", 
        //     ethertype, packet_len, eth_offset);
        return layers; // Unsupported or malformed IP
    }
    
    // If target protocol specified, check if it matches
    if (target_protocol != 0 && layers.l4_protocol != target_protocol) {
        // LOG(LogLevel::DEBUG, "parse_packet_layers: INVALID - protocol mismatch (want %u, got %u)", 
        //     target_protocol, layers.l4_protocol);
        return layers; // Protocol mismatch
    }
    
    // Parse L4 header based on protocol
    uint32_t l4_offset = eth_offset + layers.ip_header_len;
    if (layers.l4_protocol == 6) { // TCP
        if (packet_len >= l4_offset + 20) { // Minimum TCP header
            layers.l4_header_len = 20; // Minimum TCP header size
            // Could parse TCP header length from data offset field if needed
            layers.l4_payload = packet + l4_offset + layers.l4_header_len;
            layers.l4_payload_len = packet_len - l4_offset - layers.l4_header_len;
        } else {
            LOG(LogLevel::DEBUG, "parse_packet_layers: INVALID - TCP packet too short (len=%u, need %u for L4)", 
                packet_len, l4_offset + 20);
            return layers;
        }
    } else if (layers.l4_protocol == 17) { // UDP
        if (packet_len >= l4_offset + 8) { // UDP header is always 8 bytes
            layers.l4_header_len = 8;
            layers.l4_payload = packet + l4_offset + 8;
            layers.l4_payload_len = packet_len - l4_offset - 8;
        } else {
            LOG(LogLevel::DEBUG, "parse_packet_layers: INVALID - UDP packet too short (len=%u, need %u for L4)", 
                packet_len, l4_offset + 8);
            return layers;
        }
    } else {
        // Other protocols - just point to the header without parsing payload
        layers.l4_header_len = 0; // Unknown header length
        layers.l4_payload = layers.l4_header;
        layers.l4_payload_len = packet_len - l4_offset;
        LOG(LogLevel::DEBUG, "parse_packet_layers: Other protocol %u (ICMP, etc.) - marked valid", layers.l4_protocol);
    }
    
    // Mark as valid if we have all required pointers
    layers.valid = (layers.eth_header != nullptr && 
                   layers.ip_header != nullptr && 
                   layers.l4_header != nullptr);
    
    if (layers.valid) {
        LOG(LogLevel::DEBUG, "parse_packet_layers: VALID - IPv%u proto=%u eth_len=%u ip_len=%u l4_len=%u payload_len=%u", 
            layers.ip_version, layers.l4_protocol, layers.eth_header_len, 
            layers.ip_header_len, layers.l4_header_len, layers.l4_payload_len);
    } else {
        LOG(LogLevel::DEBUG, "parse_packet_layers: INVALID - missing required pointers (eth=%p ip=%p l4=%p)", 
            layers.eth_header, layers.ip_header, layers.l4_header);
    }
    
    return layers;
}

// -----------------------------------------------------------------------------
// Helpers: UMEM and Socket Setup
// -----------------------------------------------------------------------------
int setup_umem(UmemArea& ua,
               uint32_t frame_count,
               uint32_t frame_size,
               uint32_t frame_headroom,
               uint32_t fill_size,
               uint32_t comp_size)
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
                      uint32_t queue_id)
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
                             uint32_t queue_id,
                             bool allow_skb_fallback)
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

int pin_current_thread_to_cpu(int cpu_id) {
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
// Global signal handling
// -----------------------------------------------------------------------------
std::atomic<bool> g_running(true);

void handle_signal(int) {
    g_running.store(false);
}