// ---------------------------------------------------------------------
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Blitzping: Sending IP packets as fast as possible in userland.
// Copyright (C) 2024  Fereydoun Memarzanjany
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <https://www.gnu.org/licenses/>.
// ---------------------------------------------------------------------


#include "./program.h"
#include "./cmdline/logger.h"
#include "./cmdline/parser.h"
#include "packet.h"
#include "socket.h"
#include "./netlib/netinet.h"
#include "./xdp_helper.h"
// #include "af_xdp.c" // or use a proper header if you prefer
extern int xdp_ping_run(const char *ifname, const char *qid_str, const char *dest_ip, int tcp_mode);

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <stdio.h>
#include <stdlib.h>
// C11 threads (glibc >=2.28, musl >=1.1.5, Windows SDK >~10.0.22620)
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
#   include <threads.h>
int __attribute__((weak)) thrd_create(
    thrd_t *thr, thrd_start_t func, void *arg
);
int __attribute__((weak)) thrd_join(
    thrd_t thr, int *res
);
#endif

#if defined(_POSIX_C_SOURCE)
#   include <unistd.h>
#   if defined(_POSIX_THREADS) && _POSIX_THREADS >= 0
#       include <pthread.h>
int __attribute__((weak)) pthread_create(
    pthread_t *thread, const pthread_attr_t *attr,
    void *(*start_routine) (void *), void *arg
);
int __attribute__((weak)) pthread_join(
    pthread_t thread, void **retval
);
#   endif
#elif defined(_WIN32)
//#
#endif



void diagnose_system(struct ProgramArgs *const program_args) {
    //bool checks_succeeded = true;

    program_args->diagnostics.runtime.endianness = check_endianness();
#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
    program_args->diagnostics.runtime.c11_threads =
        (&thrd_create != NULL) && (&thrd_join != NULL);
#endif
#if defined(_POSIX_THREADS) && _POSIX_THREADS >= 0
    program_args->diagnostics.runtime.posix_threads =
        (&pthread_create != NULL) && (&pthread_join != NULL);
#endif
    program_args->diagnostics.runtime.num_cores =
#if defined(_POSIX_C_SOURCE)
        sysconf(_SC_NPROCESSORS_ONLN);
#else
        0;
#endif

/*
// TODO: use capabilities to also verify privilage level in raw sockets
    // Check to see if the currently running machine's endianness
    // matches what was expected to be the target's endianness at
    // the time of compilation.
#if defined(__LITTLE_ENDIAN__)
    if (runtime_endianness != little_endian) {
        logger(LOG_ERROR,
            "Program was compiled for little endian,\n"
            "but this machine is somehow big endian!\n"
        );
#elif defined(__BIG_ENDIAN__)
    if (runtime_endianness != big_endian) {
        logger(LOG_ERROR,
            "Program was compiled for big endian,\n"
            "but this machine is somehow little endian!\n"
        );
#endif
        checks_succeeded = false;
    }

    if (!thrd_create || !thrd_join) {
        fprintf(stderr,
            "This program was compiled with C11 <threads.h>,\n"
            "but this system appears to lack thrd_create() or\n"
            "thrd_join(); this could be due to an old C library.\n"
            "try using \"--native-threads\" for POSIX/Win32\n"
            "threads or \"--num-threads=0\" to disable threading.\n"
        );
        return 1;
    }
    
    fprintf(stderr,
        "This program was compiled without C11 <threads.h>;\n"
        "try using \"--native-threads\" for POSIX/Win32\n"
        "threads or \"--num-threads=0\" to disable threading.\n"
    );
*/
    //return checks_succeeded;
}

void fill_defaults(struct ProgramArgs *const program_args) {
    // General
    program_args->general.logger_level = LOG_INFO;

    // Advanced
    program_args->advanced.num_threads =
        program_args->diagnostics.runtime.num_cores;

    // IPv4
    //
    // NOTE: Unfortunately, there is no POSIX-compliant way to
    // get the current interface's ip address; getifaddrs() is
    // not standardized.
    // TODO: Use unprivilaged sendto() as an alternative.
    *(program_args->ipv4) = (struct ip_hdr){
        .ver = 4,
        .ihl = 5,
        .ttl = 128,
        .proto = IP_PROTO_TCP,
        .len = htons(sizeof(struct ip_hdr) + sizeof(struct tcp_hdr)),
        .saddr.address = 0,
        .daddr.address = 0
    };
}

int main(int argc, char *argv[]) {
    struct ProgramArgs program_args = {0};
    struct ip_hdr *ipv4_header_args = 
        (struct ip_hdr *)calloc(1, sizeof(struct ip_hdr));

    if (ipv4_header_args == NULL) {
        program_args.diagnostics.unrecoverable_error = true;
        logger(LOG_ERROR,
            "Failed to allocate memory for program arguments.");
        goto CLEANUP;
    }
    program_args.ipv4 = ipv4_header_args;

    // Check for AF_XDP flag first
    bool use_af_xdp = false;
    char *af_xdp_ifname = NULL;
    char *af_xdp_qid = "0";
    char *dest_ip = "10.10.10.10";  // Default destination
    bool tcp_mode = false;          // Default is ICMP mode

    // Create a new array for filtered arguments
    int filtered_argc = 1; // Start with program name
    char **filtered_argv = malloc(argc * sizeof(char *));
    if (!filtered_argv) {
        logger(LOG_ERROR, "Failed to allocate memory for argument filtering");
        return EXIT_FAILURE;
    }
    filtered_argv[0] = argv[0]; // Program name
    
    // Process all arguments looking for AF_XDP options
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--af-xdp") == 0) {
            use_af_xdp = true;
            if ((i + 2) < argc) {
                af_xdp_ifname = argv[i + 1];
                af_xdp_qid = argv[i + 2];
                i += 2; // Skip the next two arguments
            }
        } else if (strcmp(argv[i], "--af-xdp-tcp") == 0) {
            use_af_xdp = true;
            tcp_mode = true;
            if ((i + 3) < argc) {
                af_xdp_ifname = argv[i + 1];
                af_xdp_qid = argv[i + 2];
                dest_ip = argv[i + 3];
                i += 3; // Skip the next three arguments
            }
        } else if (strcmp(argv[i], "--dest-ip") == 0 && i + 1 < argc) {
            dest_ip = argv[i + 1];
            // Add this to filtered args since it's relevant for both modes
            filtered_argv[filtered_argc++] = argv[i];
            filtered_argv[filtered_argc++] = argv[i + 1];
            i++; // Skip the next argument (value)
        } else {
            // Add all other arguments to the filtered list
            filtered_argv[filtered_argc++] = argv[i];
        }
    }

    diagnose_system(&program_args);
    fill_defaults(&program_args);

    // If using AF_XDP, run it directly
    if (use_af_xdp && af_xdp_ifname) {
        logger(LOG_INFO, "Running with optimized AF_XDP on interface %s, queue %s%s",
               af_xdp_ifname, af_xdp_qid, 
               tcp_mode ? " in TCP flood mode" : "");
           
        // Apply XDP optimizations
        xdp_optimize_system(af_xdp_ifname, atoi(af_xdp_qid));
           
        free(filtered_argv);
        return xdp_ping_run(af_xdp_ifname, af_xdp_qid, dest_ip, tcp_mode);
    }

    // Only parse other args if not using AF_XDP
    if (parse_args(filtered_argc, filtered_argv, &program_args) != 0) {
        program_args.diagnostics.unrecoverable_error = true;
        logger(LOG_INFO, "Quitting due to invalid arguments.");
        free(filtered_argv);
        goto CLEANUP;
    }
    
    free(filtered_argv); // We're done with the filtered arguments

    logger_set_level(program_args.general.logger_level);
    logger_set_timestamps(!program_args.advanced.no_log_timestamp);

    int socket_descriptor = setup_posix_socket(
        true, !program_args.advanced.no_async_sock
    ); // TODO: make raw sockets optional
    if (socket_descriptor == -1) {
        program_args.diagnostics.unrecoverable_error = true;
        logger(LOG_INFO, "Quitting after failing to create a socket.");
        goto CLEANUP;
    }

    program_args.socket = socket_descriptor;

    send_packets(&program_args);

    if (shutdown(socket_descriptor, SHUT_RDWR) == -1) {
        logger(LOG_WARN, "Socket shutdown failed: %s", strerror(errno));
    }
    else {
        logger(LOG_INFO, "Socket shutdown successfully.");
    }

    if (close(socket_descriptor) == -1) {
        logger(LOG_WARN, "Socket closing failed: %s", strerror(errno));
    }
    else {
        logger(LOG_INFO, "Socket closed successfully.");
    }

CLEANUP:

    free(ipv4_header_args);

    logger(LOG_INFO, "Done; exiting program...");

    if (program_args.diagnostics.unrecoverable_error) {
        return EXIT_FAILURE;
    }
    else {
        return EXIT_SUCCESS;
    }
}


// ---------------------------------------------------------------------
// END OF FILE: main.c
// ---------------------------------------------------------------------
