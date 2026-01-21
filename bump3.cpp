// bump.cpp
#include <iostream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <algorithm>
#include <thread>
#include <atomic>
#include <csignal>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>   // sendto
#include <cstdio>         // perror, fprintf
#include <cerrno>
#include <arpa/inet.h>    // ntohs
#include <linux/if_link.h> // XDP_FLAGS_*
#include <xdp/xsk.h>


#ifndef XSK_BIND_FLAGS_ZEROCOPY
#define XSK_BIND_FLAGS_ZEROCOPY (1u << 0)
#endif

// -----------------------------
// Simple resource structs
// -----------------------------
struct UmemArea {
    void*               buffer = nullptr;   // backing memory
    uint64_t            size = 0;           // total bytes
    uint32_t            frame_size = 2048;  // bytes per frame
    uint32_t            frame_headroom = 0; // bytes before packet
    uint32_t            frame_count = 0;    // number of frames
    uint64_t            next_frame = 0;     // next frame index to hand out (for fill prefill)

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

// -----------------------------
// Helpers: UMEM address & free-list
// -----------------------------

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

// -----------------------------
// EtherType parsing (VLAN aware) for debug
// -----------------------------
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
        if (len < off + 4 + 2) return false; // ensure space for VLAN + next ethtype
        off += 4; // skip TCI
        if (!read_be16(frame + off, et)) return false;
    }

    ether_type_out = et;
    return true;
}

// -----------------------------
// Helpers: UMEM and Socket Setup
// -----------------------------

// Allocate and initialize UMEM (fill/comp rings).
// Returns 0 on success, non-zero on failure.
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

// Create an AF_XDP socket bound to ifname/queue_id with given UMEM and rings.
// Returns 0 on success, non-zero on failure.
int setup_rings(const char* ifname,
                uint32_t queue_id,
                UmemArea& ua,
                struct xsk_socket_config& cfg,
                XskEndpoint& ep)
{
    int ret = xsk_socket__create(&ep.xsk, ifname, queue_id, ua.umem, &ep.rx, &ep.tx, &cfg);
    if (ret) {
        std::cerr << "xsk_socket__create(" << ifname << ", q=" << queue_id
                  << ") failed: " << ret << "\n";
        return 1;
    }
    ep.fd = xsk_socket__fd(ep.xsk);
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

// Convenience wrapper that creates and logs a socket on a device.
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
    std::cout << "Created XSK socket on interface: " << ifname
              << " (queue " << queue_id << ")\n";
    return 0;
}

// -----------------------------
// Forwarding: RX -> copy -> TX -> recycle (with EtherType debug)
// -----------------------------
void forward_step(const char* tag,
                  XskEndpoint& in_ep, UmemArea& in_umem,
                  XskEndpoint& out_ep, UmemArea& out_umem,
                  bool debug_print = false)
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
    if (debug_print)
    {
   
        for (unsigned int i = 0; i < rcvd; ++i) {
            const uint8_t* frame = umem_ptr(in_umem, rx_addrs[i]);
            uint16_t et = 0;
            if (parse_ethertype_vlan_aware(frame, rx_lens[i], et)) {
                std::fprintf(stderr, "[%s RX] len=%u ethertype=0x%04x (%s)\n",
                            tag, rx_lens[i], et, ethertype_to_str(et));
            } else {
                std::fprintf(stderr, "[%s RX] len=%u ethertype=? (frame too short/malformed)\n",
                            tag, rx_lens[i]);
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

// -----------------------------
// Thread loop: poll + forward in one direction
// -----------------------------
void forward_loop(const char* tag,
                  XskEndpoint& in_ep, UmemArea& in_umem,
                  XskEndpoint& out_ep, UmemArea& out_umem,
                  std::atomic<bool>& stop_flag)
{
    struct pollfd pfd;
    pfd.fd = in_ep.fd;
    pfd.events = POLLIN;

    while (!stop_flag.load(std::memory_order_relaxed)) {
        int pr = poll(&pfd, 1, 100); // 100ms timeout
        if (pr < 0) {
            if (errno == EINTR) continue; // interrupted by signal
            perror("poll");
            break;
        }
        forward_step(tag, in_ep, in_umem, out_ep, out_umem);
    }
}

// -----------------------------
// Global stop flag via SIGINT
// -----------------------------
static std::atomic<bool>* g_stop_ptr = nullptr;
extern "C" void handle_sigint(int) {
    if (g_stop_ptr) g_stop_ptr->store(true);
}

// -----------------------------
// Main
// -----------------------------
int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <netdev_A> <netdev_B>\n";
        return 1;
    }

    const char* devA = argv[1];
    const char* devB = argv[2];

    std::cout << "Device A: " << devA << "\n";
    std::cout << "Device B: " << devB << "\n";

    // Socket configuration (copy mode)
    struct xsk_socket_config cfg {};
    cfg.rx_size = 4096;
    cfg.tx_size = 4096;
    cfg.libbpf_flags = 0; // set XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD if you will load your own XDP prog
    cfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE; // try native driver mode
    cfg.bind_flags = XSK_BIND_FLAGS_ZEROCOPY ; // copy mode (no zerocopy request)
    cfg.bind_flags = 0 ; // copy mode (no zerocopy request)


    // Parameters
    const uint32_t FRAME_COUNT = 8192; // tune as needed
    const uint32_t FRAME_SIZE  = 2048; // must hold your MTU (1500 -> OK)
    const uint32_t HEADROOM    = 0;
    const uint32_t TX_RESERVE  = 1024; // frames reserved for TX freelist on each UMEM

    // --- Setup UMEM for each endpoint (one UMEM per device) ---
    UmemArea umemA {};
    UmemArea umemB {};

    if (setup_umem(umemA, FRAME_COUNT, FRAME_SIZE, HEADROOM)) {
        std::cerr << "Failed to setup UMEM for " << devA << "\n";
        return 1;
    }
    if (setup_umem(umemB, FRAME_COUNT, FRAME_SIZE, HEADROOM)) {
        std::cerr << "Failed to setup UMEM for " << devB << "\n";
        xsk_umem__delete(umemA.umem); free(umemA.buffer);
        return 1;
    }

    // --- Create AF_XDP sockets and map rings ---
    XskEndpoint epA {}; // bound to devA (RX/TX)
    XskEndpoint epB {}; // bound to devB (RX/TX)

    if (create_xsk_socket(devA, epA, umemA, cfg, /*queue_id=*/0)) {
        xsk_umem__delete(umemB.umem); free(umemB.buffer);
        xsk_umem__delete(umemA.umem); free(umemA.buffer);
        return 1;
    }
    if (create_xsk_socket(devB, epB, umemB, cfg, /*queue_id=*/0)) {
        xsk_socket__delete(epA.xsk);
        xsk_umem__delete(umemB.umem); free(umemB.buffer);
        xsk_umem__delete(umemA.umem); free(umemA.buffer);
        return 1;
    }

    // --- Prefill each device's fill ring, reserving some frames for TX ---
    uint32_t fillA = prefill_fill_ring_n(umemA, std::max(0u, umemA.frame_count - TX_RESERVE));
    init_free_frames_from_remaining(umemA);
    uint32_t fillB = prefill_fill_ring_n(umemB, std::max(0u, umemB.frame_count - TX_RESERVE));
    init_free_frames_from_remaining(umemB);

    std::cout << devA << ": prefilled " << fillA
              << " frames, TX free " << umemA.free_frames.size() << "\n";
    std::cout << devB << ": prefilled " << fillB
              << " frames, TX free " << umemB.free_frames.size() << "\n";

    std::cout << "Sockets created and rings mapped. Starting bidirectional forwarding with threads...\n";

    // Install SIGINT handler to stop threads gracefully
    std::atomic<bool> stop{false};
    g_stop_ptr = &stop;
    std::signal(SIGINT, handle_sigint);

    // Launch threads: A->B and B->A
    std::thread th_ab([&]{
        forward_loop("A->B", epA, umemA, epB, umemB, stop);
    });
    std::thread th_ba([&]{
        forward_loop("B->A", epB, umemB, epA, umemA, stop);
    });

    // Wait for both threads
    th_ab.join();
    th_ba.join();

    // Cleanup
    xsk_socket__delete(epB.xsk);
    xsk_socket__delete(epA.xsk);
    xsk_umem__delete(umemB.umem); free(umemB.buffer);
    xsk_umem__delete(umemA.umem); free(umemA.buffer);
    return 0;
}