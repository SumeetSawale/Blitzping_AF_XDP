// ---------------------------------------------------------------------
// SPDX-License-Identifier: GPL-3.0-or-later
// socket.c is a part of Blitzping.
// ---------------------------------------------------------------------


#include "socket.h"


#if defined(_POSIX_C_SOURCE)

// NOTE: Document somewhere that raw sockets would require
// enabling the "Mirrored" networking mode for WSL2.
int setup_posix_socket(const bool is_raw, const bool is_async) {
    // Setting the 'errno' flag to 0 indicates "no errors" so
    // that a previously set value does not affect us.
    errno = 0;

    int sock_opts = 0;
    sock_opts |= is_raw ? SOCK_RAW : SOCK_STREAM;

    // Attempt to create the specified socket.
    // https://stackoverflow.com/questions/49309029
    // TODO: Kernel fills-in IPs whenever they are zero'ed; find
    // a way to actually let the 0 pass unchanged.
    // TODO: see if pf_packet + bind() is faster
    // TODO: MSG_DONTROUTE?
    // TODO: MSG_OOB  and out-of-bound?
    int socket_descriptor = socket(
        AF_INET,    // Domain
        sock_opts,  // Type (+ options)
        IPPROTO_RAW // Protocol (implies IP_HDRINCL)
    );

	if (socket_descriptor == -1) {
		// Socket creation failed (maybe non-root privileges?)
        logger(LOG_CRIT,
                "Failed to create POSIX socket: %s", strerror(errno));
        return -1;
	}

    // NOTE: This, under Linux, would have been a one-liner:
    //     sock_opts |= is_async ? SOCK_NONBLOCK : 0;
    // Unfortunately, that is a Linux-only and non-POSIX-compliant way;
    // POSIX 2001 requires using O_NONBLOCK with fcntl() instead.
    if (is_async) {
        // Get the current flags for the socket
        int flags = fcntl(socket_descriptor, F_GETFL, 0);
        if (flags == -1) {
            logger(LOG_ERROR,
                "Failed to get socket flags: %s", strerror(errno));
            return -1;
        }

        flags |= O_NONBLOCK;

        int status = fcntl(socket_descriptor, F_SETFL, flags);
        if (status == -1) {
            logger(LOG_ERROR,
                "Failed to set socket to asynchronous mode: %s",
                strerror(errno));
            return -1;
        }
    }


    return socket_descriptor;
}

#   if defined(__linux__)

// AF_PACKET + SOCK_RAW is the "lowest" you can go in terms of raw
// sockets; they're also known as a packet-socket.  However, unlike
// the above function, they aren't POSIX-compliant.
//     The most important advantage of packet-sockets is that they
// let you memory-map (mmap) them using shared ring buffers, bypassing
// most kernel layers and removing some of the overhead of syscalls:
//     https://stackoverflow.com/questions/49309029
//     https://docs.kernel.org/networking/packet_mmap.html
//     https://blog.cloudflare.com/kernel-bypass/
//     https://stackoverflow.com/questions/4873956/
int setup_mmap_socket(const char *const interface_name) {
    // NOTE: A protocol of 0 means we only want to transmit packets via
    // this socket; this will avoid expensive syscalls to packet_rcv().
    const int socket_descriptor = socket(
        AF_PACKET,
        SOCK_RAW,
        0
    );
    if (socket_descriptor == -1) {
        logger(LOG_CRIT,
            "Failed to create packet-socket: %s", strerror(errno));
        return -1;
    }

    // Identifies the link-layer "address" and protocol:
    //     https://stackoverflow.com/questions/70995951/
    // TODO: On systems with multiple network interfaces, see if
    // passing 0 to sll_ifindex improves performance.
    const struct sockaddr_ll socket_address = {
        .sll_family = AF_PACKET,
        .sll_protocol = 0,
        .sll_ifindex = if_nametoindex(interface_name)
    };
    if (socket_address.sll_ifindex == 0) {
        logger(LOG_CRIT,
            "Failed to get interface index: %s", strerror(errno));
        return -1;
    }

    // Bind the socket
    const int bind_status = bind(
        socket_descriptor,
        (struct sockaddr*)&socket_address,
        sizeof(socket_address)
    );
    if (bind_status == -1) {
        logger(LOG_ERROR,
            "Failed to bind the socket: %s", strerror(errno));
        return -1;
    }

    // Set up the PACKET_TX_RING option
    // TODO: Make these configurable and also calculate maximums
    // https://www.kernel.org/doc/Documentation/networking/pktgen.txt
    // https://www.reddit.com/r/golang/comments/1bcexhp/
    const struct tpacket_req ring_buffer_cfg = {
        .tp_block_size = 4096,
        .tp_block_nr = 64,
        .tp_frame_size = 4096,
        .tp_frame_nr = 64
    };
    const int opt_status = setsockopt(
        socket_descriptor,
        SOL_PACKET,
        PACKET_TX_RING,
        &ring_buffer_cfg,
        sizeof(ring_buffer_cfg)
    );
    if (opt_status == -1) {
        logger(LOG_ERROR,
            "Failed to set PACKET_TX_RING option: %s", strerror(errno));
        return -1;
    }

    // Memory-map the ring buffer to user-space
    const void *const map = mmap(
        NULL,
        ring_buffer_cfg.tp_block_size * ring_buffer_cfg.tp_block_nr,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        socket_descriptor,
        0
    );
    if (map == MAP_FAILED) {
        logger(LOG_ERROR,
            "Failed to memory-map packet-socket's ring buffer: %s",
            strerror(errno)
        );
        return -1;
    }

    // TODO: PACKET_QDISC_BYPASS seems very promising  (kernel 3.14+)
    // TODO: MSG_ZEROCOPY vs. af_packet?
    
    // The socket is now ready to use with the mapped buffer
    return socket_descriptor;
}

// TODO: Investigate AF_XDP, as it appears to have the potential to
// be faster than packet-sockets, but it might also require loading
// BPF objects into kernel and/or having specific models of NICs. (?)
// Other than running directly on the NIC (where very few smartNICs
// even support this capability), you can also hook the XDP in the
// driver itself (again, without widespreads upport); finally,
// you may also run the XDP in a "generic" SKB mode, which seems to
// defeat its performance benefits and also prevent zero-copy'ing.
//     https://www.youtube.com/watch?v=hO2tlxURXJ0
//     https://qmonnet.github.io/whirl-offload/2016/09/01/dive-into-bpf
//     https://github.com/xdp-project/
//         xdp-project/blob/master/areas/drivers/README.org
//     https://pantheon.tech/what-is-af_xdp
//     https://stackoverflow.com/questions/78990613/
//     https://forum.suricata.io/t/
//         difference-between-af-packet-mode-and-af-xdp-mode/4754
//     https://stackoverflow.com/questions/
//     https://blog.cloudflare.com/
//         a-story-about-af-xdp-network-namespaces-and-a-cookie/
//     https://blog.freifunk.net/2024/05/31/gsoc-2024-ebpf-
//         performance-optimizations-for-a-new-openwrt-firewall/
//     https://toonk.io/building-an-xdp-express-data-path-
//         based-bgp-peering-router/index.html
//     https://www.netdevconf.org/0x14/pub/slides/37/
//         Adding%20AF_XDP%20zero-copy%20support%20to%20drivers.pdf
// Also, it appears that AF_XDP is the "successor" to AF_PACKET v3;
// AF_PACKET v4 never seems to have taken off (?):
//     https://lore.kernel.org/netdev/
//         95aaafdc-ef8a-c4b9-6104-a1a753c81820@intel.com/
//     https://lwn.net/Articles/737947/
//     https://www.netdevconf.info/2.2/slides/karlsson-afpacket-talk.pdf
//     https://www.youtube.com/watch?v=RSFX7z1qF2g
//
// Ultimately, it appears that the "fastest" method is to write our
// own driver for a specific NIC, but that is obviously not portable.
// (DPDK, VPP, libpcap, etc. do exactly this for a handful of NICs.)

#   endif /* defined(__linux__) */

#endif /* defined(_POSIX_C_SOURCE) */


// ---------------------------------------------------------------------
// END OF FILE: socket.c
// ---------------------------------------------------------------------
