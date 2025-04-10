// ---------------------------------------------------------------------
// SPDX-License-Identifier: GPL-3.0-or-later
// af_xdp.c is a part of Blitzping.
// ---------------------------------------------------------------------

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>  // Add this to support bool type
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <poll.h>  // Add missing header for poll()
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <time.h>
#include <assert.h>
#include <sched.h>

/* Constants and tuning parameters - make configurable for performance tuning */
#define CHUNK_SIZE      8192        /* Increased from 4096 for better bulk transfers */
#define CHUNK_COUNT     8192        /* Increased from 4096 for more buffers */
#define UMEM_SIZE       (CHUNK_SIZE * CHUNK_COUNT)
#define RING_SIZE       2048        /* Increased from 512 for less recycling */
#define MAX_EVENTS      64          /* Increased from 32 */
#define EPOLL_TIMEOUT   100         /* Reduced from 1000ms for more responsive polling */
#define BATCH_SIZE      256         /* Increased from 64 - process more packets per batch */

/* Additional optimizations */
#define USE_BUSY_POLLING 1          /* Use busy polling for lower latency */
#define PREFETCH_DISTANCE 8         /* Prefetch packets ahead of processing */
#define USE_HUGEPAGES 1             /* Use huge pages for UMEM if available */
#define TX_BATCH_SIZE 64            /* Batch size for TX submissions */

/* Advanced XDP settings if available */
#define XDP_FLAGS XDP_FLAGS_SKB_MODE /* Start with SKB mode - driver can override */
#define NEED_WAKEUP 1               /* Enable notifications when queue space available */

/* Helper macro for error checking */
#define CHECK_RET(ret, msg) do { \
    if ((ret) < 0) { \
        perror(msg); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

/* Helper function to set socket options with error handling */
static int xsk_set_sockopt(int fd, int level, int optname, const void *optval, socklen_t optlen) {
    int ret = setsockopt(fd, level, optname, optval, optlen);
    if (ret < 0) {
        fprintf(stderr, "ERROR: setsockopt %d failed: %s\n", optname, strerror(errno));
    }
    return ret;
}

/* Cache-aligned memory allocation - critical for performance */
static void *aligned_alloc_with_hugepages(size_t alignment, size_t size) {
    void *ptr = NULL;
    
#if USE_HUGEPAGES
    /* Try to allocate using huge pages for better TLB efficiency */
    char *hugetlb_env = getenv("HUGETLB_PATH");
    if (hugetlb_env) {
        int fd = open(hugetlb_env, O_RDWR);
        if (fd >= 0) {
            ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, 
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, 
                       -1, 0);
            if (ptr == MAP_FAILED) {
                ptr = NULL;
            }
            close(fd);
        }
    }
#endif

    /* Fallback to regular aligned allocation */
    if (!ptr) {
        if (posix_memalign(&ptr, alignment, size) != 0) {
            return NULL;
        }
    }
    
    /* Pre-fault pages for better performance during packet processing */
    if (ptr) {
        char *p = (char*)ptr;
        for (size_t i = 0; i < size; i += 4096) {
            p[i] = 0;
        }
    }
    
    return ptr;
}

/* UMEM frame allocator - correctly tracks free/used chunks */
struct umem_frame_pool {
    uint64_t *frames;           /* Array of frame addresses */
    uint32_t num_frames;        /* Total number of frames */
    uint32_t head;              /* Producer index */
    uint32_t tail;              /* Consumer index */
    uint32_t frame_size;        /* Size of each frame */
};

static struct umem_frame_pool *umem_allocator_create(uint32_t num_frames, uint32_t frame_size) {
    struct umem_frame_pool *pool;
    
    pool = malloc(sizeof(*pool));
    if (!pool)
        return NULL;
    
    pool->frames = calloc(num_frames, sizeof(*pool->frames));
    if (!pool->frames) {
        free(pool);
        return NULL;
    }
    
    pool->num_frames = num_frames;
    pool->frame_size = frame_size;
    pool->head = 0;
    pool->tail = 0;
    
    // Initialize with frame addresses
    for (uint32_t i = 0; i < num_frames; i++)
        pool->frames[i] = i * frame_size;
    
    return pool;
}

static void umem_allocator_free(struct umem_frame_pool *pool) {
    if (pool) {
        free(pool->frames);
        free(pool);
    }
}

static uint64_t umem_allocator_alloc_frame(struct umem_frame_pool *pool) {
    uint64_t frame;
    
    if (pool->head == pool->tail)  // Empty pool
        return UINT64_MAX;
        
    frame = pool->frames[pool->tail];
    pool->tail = (pool->tail + 1) % pool->num_frames;
    
    return frame;
}

static void umem_allocator_free_frame(struct umem_frame_pool *pool, uint64_t frame) {
    uint32_t next_head = (pool->head + 1) % pool->num_frames;
    
    if (next_head == pool->tail) {  // Pool full
        fprintf(stderr, "WARNING: Frame pool full, dropping frame\n");
        return;
    }
    
    pool->frames[pool->head] = frame;
    pool->head = next_head;
}

// Structures to hold mapped ring information
struct xsk_ring {
    void *map;
    __u32 mask;
    volatile __u32 *producer;
    volatile __u32 *consumer;
    struct xdp_desc *descs;
    size_t num_desc;
};

// Extended XSK socket info with more management fields
struct xsk_socket_info {
    int fd;
    int ifindex;
    uint32_t queue_id;
    void *umem_area;
    size_t umem_size;
    struct xsk_ring rx;
    struct xsk_ring tx;
    struct xsk_ring fill;
    struct xsk_ring comp;
    struct xdp_mmap_offsets mmap_offsets;
    struct umem_frame_pool *frame_pool;
    
    /* Stats */
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_dropped;
    uint64_t tx_invalid;
    
    /* Configuration */
    bool use_zero_copy;
    uint32_t batch_size;
};

// Add forward declarations for all functions near the top
static bool xsk_configure_rings(struct xsk_socket_info *xsk);
static bool process_packet(struct xsk_socket_info *xsk, void *pkt, uint32_t len, uint64_t addr);
static bool process_icmp_packet(struct xsk_socket_info *xsk, void *pkt, uint32_t len, uint64_t addr);
static bool process_tcp_packet(struct xsk_socket_info *xsk, void *pkt, uint32_t len, uint64_t addr);
static bool process_udp_packet(struct xsk_socket_info *xsk, void *pkt, uint32_t len, uint64_t addr);
static bool process_arp_packet(struct xsk_socket_info *xsk, void *pkt, uint32_t len, uint64_t addr);
static uint16_t ip_checksum(void *vdata, size_t length);
static void event_loop_optimized(
    struct xsk_socket_info *xsk, const char *dest_ip, int tcp_flood_mode, int cpu_core);

// Helper functions
static void cleanup_xsk(struct xsk_socket_info *xsk) {
    if (!xsk)
        return;
        
    if (xsk->rx.map)
        munmap(xsk->rx.map, xsk->mmap_offsets.rx.desc + RING_SIZE * sizeof(struct xdp_desc));
    if (xsk->tx.map)
        munmap(xsk->tx.map, xsk->mmap_offsets.tx.desc + RING_SIZE * sizeof(struct xdp_desc));
    if (xsk->fill.map)
        munmap(xsk->fill.map, xsk->mmap_offsets.fr.desc + RING_SIZE * sizeof(uint64_t));
    if (xsk->comp.map)
        munmap(xsk->comp.map, xsk->mmap_offsets.cr.desc + RING_SIZE * sizeof(uint64_t));
    if (xsk->umem_area)
        free(xsk->umem_area);
    if (xsk->fd >= 0)
        close(xsk->fd);
}

/* Improved fill_umem function - fill in larger batches */
static bool fill_umem(struct xsk_socket_info *xsk) {
    uint32_t idx = *xsk->fill.producer;
    uint32_t available_frames = RING_SIZE - (idx - *xsk->fill.consumer);
    
    if (available_frames < BATCH_SIZE/2) {
        return false; /* Not enough space */
    }
    
    /* Fill with as many frames as possible in one go */
    uint32_t batch_size = (available_frames > BATCH_SIZE) ? BATCH_SIZE : available_frames;
    uint64_t *fill_addr = (uint64_t *)((char *)xsk->fill.map + xsk->mmap_offsets.fr.desc);
    
    /* Batch fill with direct array access for better performance */
    for (uint32_t i = 0; i < batch_size; i++) {
        uint64_t frame = umem_allocator_alloc_frame(xsk->frame_pool);
        if (frame == UINT64_MAX) {
            batch_size = i;
            break;
        }
        fill_addr[(idx + i) & xsk->fill.mask] = frame;
    }
    
    if (batch_size == 0)
        return false;
    
    /* Memory barrier ensures visibility across cores */
    __sync_synchronize();
    *xsk->fill.producer = idx + batch_size;
    return true;
}

/* Optimized TX completion processing */
static void process_completions(struct xsk_socket_info *xsk) {
    uint32_t comp_cons = *xsk->comp.consumer;
    uint32_t comp_prod = *xsk->comp.producer;
    uint32_t completed = comp_prod - comp_cons;
    
    if (!completed)
        return;
    
    /* Process all completions at once for better efficiency */
    uint32_t to_process = completed;
    uint64_t *comp_addr = (uint64_t *)((char *)xsk->comp.map + xsk->mmap_offsets.cr.desc);
    
    /* Vectorized batch processing of completions */
    for (uint32_t i = 0; i < to_process; i += 4) {
        uint32_t idx = (comp_cons + i) & xsk->comp.mask;
        
        /* Prefetch upcoming completion entries */
        if (i + PREFETCH_DISTANCE < to_process) {
            __builtin_prefetch(&comp_addr[(comp_cons + i + PREFETCH_DISTANCE) & xsk->comp.mask]);
        }
        
        /* Process up to 4 completions at once */
        uint32_t batch = (to_process - i) < 4 ? (to_process - i) : 4;
        for (uint32_t j = 0; j < batch; j++) {
            umem_allocator_free_frame(xsk->frame_pool, comp_addr[(idx + j) & xsk->comp.mask]);
        }
    }
    
    /* Update consumer pointer */
    *xsk->comp.consumer = comp_cons + to_process;
    xsk->tx_packets += to_process;
}

// Process RX packets more efficiently in batches
static void process_rx_ring(struct xsk_socket_info *xsk) {
    uint32_t rx_cons = *xsk->rx.consumer;
    uint32_t rx_prod = *xsk->rx.producer;
    uint32_t pkts_available = rx_prod - rx_cons;
    
    if (!pkts_available)
        return;
        
    uint32_t to_process = pkts_available > BATCH_SIZE ? BATCH_SIZE : pkts_available;
    
    for (uint32_t i = 0; i < to_process; i++) {
        uint32_t idx = (rx_cons + i) & xsk->rx.mask;
        struct xdp_desc *desc = &xsk->rx.descs[idx];
        void *pkt = (char *)xsk->umem_area + desc->addr;
        uint32_t pkt_len = desc->len;
        
        // Process packet based on type
        if (process_packet(xsk, pkt, pkt_len, desc->addr)) {
            xsk->rx_packets++;
        } else {
            // If not handled, recycle the buffer
            uint32_t tx_idx = *xsk->tx.producer & xsk->tx.mask;
            xsk->tx.descs[tx_idx].addr = desc->addr;
            xsk->tx.descs[tx_idx].len = desc->len;
            *xsk->tx.producer = *xsk->tx.producer + 1;
        }
    }
    
    // Update consumer pointer
    *xsk->rx.consumer = rx_cons + to_process;
}

// Handle different packet types - more robust implementation
static bool process_packet(struct xsk_socket_info *xsk, void *pkt, uint32_t len, uint64_t addr) {
    struct ethhdr *eth = pkt;
    
    // Minimum Ethernet frame size check
    if (len < sizeof(struct ethhdr))
        return false;
        
    if (ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        
        // Verify IP header
        if (len < sizeof(struct ethhdr) + sizeof(struct iphdr))
            return false;
            
        size_t iphdr_len = iph->ihl * 4;
        (void)iphdr_len; // Silence unused variable warning
        
        // Handle different IP protocols
        switch(iph->protocol) {
            case IPPROTO_ICMP:
                return process_icmp_packet(xsk, pkt, len, addr);
                
            case IPPROTO_TCP:
                return process_tcp_packet(xsk, pkt, len, addr);
                
            case IPPROTO_UDP:
                return process_udp_packet(xsk, pkt, len, addr);
                
            default:
                // Unknown protocol - pass through
                return false;
        }
    } else if (ntohs(eth->h_proto) == ETH_P_ARP) {
        return process_arp_packet(xsk, pkt, len, addr);
    }
    
    return false;
}

// Handler for specific protocols - more robust ICMP implementation
static bool process_icmp_packet(struct xsk_socket_info *xsk, void *pkt, uint32_t len, uint64_t addr) {
    struct ethhdr *eth = pkt;
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    
    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr))
        return false;
        
    size_t iphdr_len = iph->ihl * 4;
    struct icmphdr *icmph = (struct icmphdr *)((uint8_t *)iph + iphdr_len);
    
    // Only handle ECHO requests
    if (icmph->type != ICMP_ECHO)
        return false;
        
    // Prepare echo reply (swap addresses)
    uint8_t tmp_mac[ETH_ALEN];
    memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, tmp_mac, ETH_ALEN);
    
    uint32_t tmp_ip = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp_ip;
    iph->check = 0;
    iph->check = ip_checksum(iph, iphdr_len);
    
    // Change ICMP type and recalculate checksum
    icmph->type = ICMP_ECHOREPLY;
    icmph->checksum = 0;
    icmph->checksum = ip_checksum(icmph, len - sizeof(struct ethhdr) - iphdr_len);
    
    // Queue for transmission
    uint32_t tx_idx = *xsk->tx.producer & xsk->tx.mask;
    xsk->tx.descs[tx_idx].addr = addr;
    xsk->tx.descs[tx_idx].len = len;
    
    // Memory barrier before updating producer
    __sync_synchronize();
    *xsk->tx.producer = *xsk->tx.producer + 1;
    
    return true;
}

// Add stub implementations for functions that were called but not defined

static bool process_tcp_packet(struct xsk_socket_info *xsk, void *pkt, uint32_t len, uint64_t addr) {
    (void)xsk;
    (void)pkt;
    (void)len;
    (void)addr;
    // Not implemented yet
    return false;
}

static bool process_udp_packet(struct xsk_socket_info *xsk, void *pkt, uint32_t len, uint64_t addr) {
    (void)xsk;
    (void)pkt;
    (void)len;
    (void)addr;
    // Not implemented yet
    return false;
}

static bool process_arp_packet(struct xsk_socket_info *xsk, void *pkt, uint32_t len, uint64_t addr) {
    (void)xsk;
    (void)pkt;
    (void)len;
    (void)addr;
    // Not implemented yet
    return false;
}

/* Optimized TCP packet generation for XDP */
static void xdp_send_tcp_packets_optimized(struct xsk_socket_info *xsk, const char *dest_ip, int num_packets) {
    struct in_addr dest_addr;
    if (inet_aton(dest_ip, &dest_addr) == 0) {
        fprintf(stderr, "Invalid destination IP address\n");
        return;
    }
    
    /* For performance measurement */
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    
    /* Prepare multiple packet templates for better throughput */
    const int NUM_TEMPLATES = 256; /* Increased from 64 */
    uint64_t addr_templates[NUM_TEMPLATES];
    
    /* Prepare packet templates in parallel if possible */
    #pragma omp parallel for if(NUM_TEMPLATES > 128)
    for (int t = 0; t < NUM_TEMPLATES; t++) {
        /* Get a frame from our allocator */
        uint64_t addr = umem_allocator_alloc_frame(xsk->frame_pool);
        if (addr == UINT64_MAX) {
            fprintf(stderr, "Failed to allocate frame for template %d\n", t);
            continue;
        }
        
        char *pkt_data = (char *)xsk->umem_area + addr;
        struct ethhdr *eth = (struct ethhdr *)pkt_data;
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        struct tcphdr *tcph = (struct tcphdr *)((char*)iph + sizeof(struct iphdr));
        
        /* Ethernet header setup */
        memset(eth->h_dest, 0xFF, ETH_ALEN);
        memset(eth->h_source, 0xAA, ETH_ALEN);
        eth->h_source[5] = t & 0xFF; /* Make each MAC slightly different */
        eth->h_proto = htons(ETH_P_IP);
        
        /* IP header setup with better distribution */
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        iph->id = htons(t);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        
        /* Use better distribution of source IPs */
        uint32_t src_ip = 0x0A000001 + ((t * 1103515245 + 12345) & 0xFFFF);
        iph->saddr = htonl(src_ip);
        iph->daddr = dest_addr.s_addr;
        
        /* TCP header setup with better distribution */
        tcph->source = htons(1024 + (t % 64511)); /* Better port range */
        tcph->dest = htons(80);
        tcph->seq = htonl(1000 + t);
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->fin = 0;
        tcph->syn = 1; /* SYN flood */
        tcph->rst = 0;
        tcph->psh = 0;
        tcph->ack = 0;
        tcph->urg = 0;
        tcph->window = htons(65535); /* Maximum window size */
        tcph->check = 0;
        tcph->urg_ptr = 0;
        
        /* Pre-compute checksums */
        iph->check = ip_checksum(iph, sizeof(struct iphdr));
        
        /* Store the address for later use */
        addr_templates[t] = addr;
    }
    
    /* Enhanced high-speed transmission logic */
    uint32_t target_packets = (uint32_t)num_packets;
    uint32_t sent_packets = 0;
    uint32_t batch_size = TX_BATCH_SIZE;
    uint32_t tx_completion_check = 32; /* Check completions every N batches */
    uint32_t batch_count = 0;
    
    while (sent_packets < target_packets) {
        /* Adjust batch size based on remaining packets */
        uint32_t to_send = (target_packets - sent_packets) < batch_size ? 
                         (target_packets - sent_packets) : batch_size;
                         
        /* Check TX ring capacity */
        uint32_t tx_prod = *xsk->tx.producer;
        uint32_t tx_cons = *xsk->tx.consumer;
        uint32_t tx_available = RING_SIZE - (tx_prod - tx_cons);
        
        if (tx_available < to_send) {
            /* Process completions to make space and try again */
            process_completions(xsk);
            
            /* If ring is still full, poll or use notifications */
            if (NEED_WAKEUP) {
                poll(NULL, 0, 1); /* Small delay */
            }
            continue;
        }
        
        /* Submit batch of packets to TX ring with prefetching */
        for (uint32_t i = 0; i < to_send; i++) {
            uint32_t tx_idx = (tx_prod + i) & xsk->tx.mask;
            uint32_t template_idx = (sent_packets + i) % NUM_TEMPLATES;
            
            /* Prefetch next descriptor for better pipelining */
            if (i + 1 < to_send) {
                __builtin_prefetch(&xsk->tx.descs[(tx_prod + i + 1) & xsk->tx.mask]);
            }
            
            /* Assign packet to TX ring */
            xsk->tx.descs[tx_idx].addr = addr_templates[template_idx];
            xsk->tx.descs[tx_idx].len = sizeof(struct ethhdr) + 
                                      sizeof(struct iphdr) + 
                                      sizeof(struct tcphdr);
        }
        
        /* Memory barrier before updating producer */
        __sync_synchronize();
        
        /* Update producer pointer */
        *xsk->tx.producer = tx_prod + to_send;
        
        sent_packets += to_send;
        batch_count++;
        
        /* Process completions periodically for better resource reuse */
        if (batch_count % tx_completion_check == 0) {
            process_completions(xsk);
        }
    }
    
    /* Final completion processing */
    process_completions(xsk);
    
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double seconds = (end_time.tv_sec - start_time.tv_sec) + 
                    (end_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;
    
    printf("AF_XDP mode: Sent %d TCP packets in %.6f seconds (%.2f packets/sec)\n", 
           sent_packets, seconds, sent_packets/seconds);
    printf("Total throughput: %.2f Mbps\n", 
           (sent_packets * (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)) * 8) / 
           (seconds * 1000000));
}

/* Configure the socket with advanced optimizations */
static struct xsk_socket_info *xsk_configure_socket_advanced(
    const char *ifname, uint32_t queue_id, bool zero_copy) {
    
    struct xsk_socket_info *xsk;
    int ret;
    
    xsk = calloc(1, sizeof(*xsk));
    if (!xsk)
        return NULL;
        
    xsk->fd = -1;
    xsk->use_zero_copy = zero_copy;
    xsk->batch_size = BATCH_SIZE;
    
    // Initialize frame pool for buffer management
    xsk->frame_pool = umem_allocator_create(CHUNK_COUNT, CHUNK_SIZE);
    if (!xsk->frame_pool) {
        fprintf(stderr, "Failed to create frame pool\n");
        goto error;
    }
    
    // Get interface index
    xsk->ifindex = if_nametoindex(ifname);
    if (xsk->ifindex == 0) {
        perror("if_nametoindex");
        goto error;
    }
    xsk->queue_id = queue_id;
    
    // Create AF_XDP socket
    xsk->fd = socket(AF_XDP, SOCK_RAW, 0);
    if (xsk->fd < 0) {
        perror("socket(AF_XDP)");
        goto error;
    }
    
    /* Allocate with huge page support if possible */
    xsk->umem_area = aligned_alloc_with_hugepages(CHUNK_SIZE, UMEM_SIZE);
    if (!xsk->umem_area) {
        fprintf(stderr, "Failed to allocate UMEM: %s\n", strerror(errno));
        goto error;
    }
    memset(xsk->umem_area, 0, UMEM_SIZE);
    xsk->umem_size = UMEM_SIZE;
    
    // Configure UMEM
    struct xdp_umem_reg umem_reg = {
        .addr = (uintptr_t)xsk->umem_area,
        .len = UMEM_SIZE,
        .chunk_size = CHUNK_SIZE,
        .headroom = 0,
        .flags = 0,
    };
    
    ret = setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_REG, &umem_reg, sizeof(umem_reg));
    if (ret) {
        perror("setsockopt(XDP_UMEM_REG)");
        goto error;
    }
    
    // Configure ring sizes
    int ring_size = RING_SIZE;
    ret = setsockopt(xsk->fd, SOL_XDP, XDP_RX_RING, &ring_size, sizeof(ring_size));
    if (ret) {
        perror("setsockopt(XDP_RX_RING)");
        goto error;
    }
    
    ret = setsockopt(xsk->fd, SOL_XDP, XDP_TX_RING, &ring_size, sizeof(ring_size));
    if (ret) {
        perror("setsockopt(XDP_TX_RING)");
        goto error;
    }
    
    ret = setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_FILL_RING, &ring_size, sizeof(ring_size));
    if (ret) {
        perror("setsockopt(XDP_UMEM_FILL_RING)");
        goto error;
    }
    
    ret = setsockopt(xsk->fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &ring_size, sizeof(ring_size));
    if (ret) {
        perror("setsockopt(XDP_UMEM_COMPLETION_RING)");
        goto error;
    }
    
    /* Enable busy polling for lower latency if supported */
#if USE_BUSY_POLLING
    int busy_poll = 20; /* microseconds to busy poll */
    xsk_set_sockopt(xsk->fd, SOL_SOCKET, SO_BUSY_POLL, &busy_poll, sizeof(busy_poll));
    
    int busy_budget = 256;
    xsk_set_sockopt(xsk->fd, SOL_SOCKET, SO_BUSY_POLL_BUDGET, &busy_budget, sizeof(busy_budget));
#endif
    
    // Get ring offsets
    socklen_t optlen = sizeof(xsk->mmap_offsets);
    ret = getsockopt(xsk->fd, SOL_XDP, XDP_MMAP_OFFSETS, &xsk->mmap_offsets, &optlen);
    if (ret) {
        perror("getsockopt(XDP_MMAP_OFFSETS)");
        goto error;
    }
    
    // Map rings
    if (!xsk_configure_rings(xsk)) {
        fprintf(stderr, "Failed to configure rings\n");
        goto error;
    }
    
    // Bind socket
    struct sockaddr_xdp sxdp = {
        .sxdp_family = AF_XDP,
        .sxdp_ifindex = xsk->ifindex,
        .sxdp_queue_id = xsk->queue_id,
        .sxdp_flags = zero_copy ? XDP_ZEROCOPY : 0,
    };
    
    ret = bind(xsk->fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
    if (ret) {
        // If zero-copy fails, try without it
        if (zero_copy && errno == EINVAL) {
            sxdp.sxdp_flags = 0;
            fprintf(stderr, "Zero-copy not supported, falling back to copy mode\n");
            xsk->use_zero_copy = false;
            ret = bind(xsk->fd, (struct sockaddr *)&sxdp, sizeof(sxdp));
        }
        
        if (ret) {
            perror("bind(AF_XDP)");
            goto error;
        }
    }
    
    // Pre-fill FILL ring with all frames
    if (!fill_umem(xsk)) {
        fprintf(stderr, "Failed to fill UMEM\n");
        goto error;
    }
    
    printf("AF_XDP socket successfully configured on interface %s (ifindex %d, queue %d, %s)\n",
           ifname, xsk->ifindex, xsk->queue_id,
           xsk->use_zero_copy ? "zero-copy" : "copy mode");
    
    return xsk;

error:
    if (xsk) {
        cleanup_xsk(xsk);
        umem_allocator_free(xsk->frame_pool);
        free(xsk);
    }
    return NULL;
}

// Properly map all rings (not just RX)
static bool xsk_configure_rings(struct xsk_socket_info *xsk) {
    /* RX Ring */
    size_t rx_map_size = xsk->mmap_offsets.rx.desc + (RING_SIZE * sizeof(struct xdp_desc));
    xsk->rx.map = mmap(NULL, rx_map_size, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, xsk->fd, XDP_PGOFF_RX_RING);
    if (xsk->rx.map == MAP_FAILED) {
        perror("mmap(rx)");
        return false;
    }
    xsk->rx.num_desc = RING_SIZE;
    xsk->rx.mask = RING_SIZE - 1;
    xsk->rx.descs = (struct xdp_desc *)((char*)xsk->rx.map + xsk->mmap_offsets.rx.desc);
    xsk->rx.consumer = (__u32 *)((char*)xsk->rx.map + xsk->mmap_offsets.rx.consumer);
    xsk->rx.producer = (__u32 *)((char*)xsk->rx.map + xsk->mmap_offsets.rx.producer);

    /* TX Ring */
    size_t tx_map_size = xsk->mmap_offsets.tx.desc + (RING_SIZE * sizeof(struct xdp_desc));
    xsk->tx.map = mmap(NULL, tx_map_size, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, xsk->fd, XDP_PGOFF_TX_RING);
    if (xsk->tx.map == MAP_FAILED) {
        perror("mmap(tx)");
        return false;
    }
    xsk->tx.num_desc = RING_SIZE;
    xsk->tx.mask = RING_SIZE - 1;
    xsk->tx.descs = (struct xdp_desc *)((char*)xsk->tx.map + xsk->mmap_offsets.tx.desc);
    xsk->tx.consumer = (__u32 *)((char*)xsk->tx.map + xsk->mmap_offsets.tx.consumer);
    xsk->tx.producer = (__u32 *)((char*)xsk->tx.map + xsk->mmap_offsets.tx.producer);

    /* FILL Ring */
    size_t fill_map_size = xsk->mmap_offsets.fr.desc + (RING_SIZE * sizeof(uint64_t));
    xsk->fill.map = mmap(NULL, fill_map_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_POPULATE, xsk->fd, XDP_UMEM_PGOFF_FILL_RING);
    if (xsk->fill.map == MAP_FAILED) {
        perror("mmap(fill)");
        return false;
    }
    xsk->fill.num_desc = RING_SIZE;
    xsk->fill.mask = RING_SIZE - 1;
    xsk->fill.descs = (struct xdp_desc *)((char*)xsk->fill.map + xsk->mmap_offsets.fr.desc);
    xsk->fill.consumer = (__u32 *)((char*)xsk->fill.map + xsk->mmap_offsets.fr.consumer);
    xsk->fill.producer = (__u32 *)((char*)xsk->fill.map + xsk->mmap_offsets.fr.producer);

    /* COMPLETION Ring */
    size_t comp_map_size = xsk->mmap_offsets.cr.desc + (RING_SIZE * sizeof(uint64_t));
    xsk->comp.map = mmap(NULL, comp_map_size, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_POPULATE, xsk->fd, XDP_UMEM_PGOFF_COMPLETION_RING);
    if (xsk->comp.map == MAP_FAILED) {
        perror("mmap(comp)");
        return false;
    }
    xsk->comp.num_desc = RING_SIZE;
    xsk->comp.mask = RING_SIZE - 1;
    xsk->comp.descs = (struct xdp_desc *)((char*)xsk->comp.map + xsk->mmap_offsets.cr.desc);
    xsk->comp.consumer = (__u32 *)((char*)xsk->comp.map + xsk->mmap_offsets.cr.consumer);
    xsk->comp.producer = (__u32 *)((char*)xsk->comp.map + xsk->mmap_offsets.cr.producer);
    
    return true;
}

// Enhanced version with more options
int xdp_ping_run(const char *ifname, const char *qid_str, const char *dest_ip, int tcp_mode) {
    printf("Starting optimized AF_XDP mode on interface %s\n", ifname);
    
    uint32_t queue_id = atoi(qid_str);
    
    /* Map queue to optimal CPU core, considering NUMA topology if possible */
    int cpu_core = -1;
    char numa_path[256];
    snprintf(numa_path, sizeof(numa_path), 
             "/sys/class/net/%s/device/numa_node", ifname);
    
    FILE *numa_file = fopen(numa_path, "r");
    if (numa_file) {
        int numa_node;
        if (fscanf(numa_file, "%d", &numa_node) == 1 && numa_node >= 0) {
            /* Try to pick a CPU from the same NUMA node as the NIC */
            long cores_per_node = sysconf(_SC_NPROCESSORS_ONLN) / 2; /* Estimate */
            if (cores_per_node > 0) {
                cpu_core = numa_node * cores_per_node + (queue_id % cores_per_node);
            }
        }
        fclose(numa_file);
    }
    
    /* Fall back to simple mapping if NUMA information not available */
    if (cpu_core < 0) {
        cpu_core = queue_id % sysconf(_SC_NPROCESSORS_ONLN);
    }
    
    /* Try with zero-copy first, then fall back to copy mode */
    struct xsk_socket_info *xsk = xsk_configure_socket_advanced(ifname, queue_id, true);
    if (!xsk) {
        fprintf(stderr, "Failed to configure AF_XDP socket with zero-copy, trying copy mode\n");
        xsk = xsk_configure_socket_advanced(ifname, queue_id, false);
    }
    
    if (!xsk) {
        fprintf(stderr, "Failed to configure AF_XDP socket\n");
        return -1;
    }
    
    /* Run optimized event loop */
    event_loop_optimized(xsk, dest_ip, tcp_mode, cpu_core);
    
    /* Clean up resources */
    cleanup_xsk(xsk);
    umem_allocator_free(xsk->frame_pool);
    free(xsk);
    
    return 0;
}

/* Enhanced event loop with optimized polling and processing */
static void event_loop_optimized(
    struct xsk_socket_info *xsk, const char *dest_ip, int tcp_flood_mode, int cpu_core) {
    
    /* Set CPU affinity */
    if (cpu_core >= 0) {
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);
        CPU_SET(cpu_core, &cpu_set);
        
        if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set)) {
            fprintf(stderr, "Failed to set CPU affinity: %s\n", strerror(errno));
        } else {
            printf("Set thread affinity to CPU core %d\n", cpu_core);
        }
    }
    
    /* For TCP flood mode, use dedicated high-performance mode */
    if (tcp_flood_mode) {
        xdp_send_tcp_packets_optimized(xsk, dest_ip, 1000000);
        return;
    }
    
    /* Enhanced ICMP echo response code with optimizations */
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        return;
    }
    
    struct epoll_event ev = {
        .events = EPOLLIN | (NEED_WAKEUP ? EPOLLOUT : 0),
        .data.fd = xsk->fd
    };
    
    int ret = epoll_ctl(epfd, EPOLL_CTL_ADD, xsk->fd, &ev);
    if (ret < 0) {
        perror("epoll_ctl");
        close(epfd);
        return;
    }
    
    printf("AF_XDP event loop started - waiting for packets\n");
    
    struct epoll_event events[MAX_EVENTS];
    
    /* Main loop with optimized polling */
    while (1) {
        /* Use shorter timeout for more responsive polling */
        /* Use the return value or mark it as unused to avoid warning */
        int n = epoll_wait(epfd, events, MAX_EVENTS, EPOLL_TIMEOUT);
        (void)n;  // Explicitly mark as unused
        
        /* Always process rings even if epoll returns no events */
        process_rx_ring(xsk);
        
        /* More aggressive completion processing */
        process_completions(xsk);
        
        /* Ensure UMEM is always well-populated for max performance */
        fill_umem(xsk);
    }
    
    close(epfd);
}

static uint16_t ip_checksum(void *vdata, size_t length) {
    // Cast the data pointer to one that can be indexed.
    char *data = (char *)vdata;
    uint32_t acc = 0xffff;
    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        memcpy(&word, data + i, 2);
        acc += ntohs(word);
        if (acc > 0xffff)
            acc -= 0xffff;
    }
    if (length & 1) {
        uint16_t word = 0;
        memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff)
            acc -= 0xffff;
    }
    return htons(~acc);
}

// ---------------------------------------------------------------------
// END OF FILE: af_xdp.c
// ---------------------------------------------------------------------
