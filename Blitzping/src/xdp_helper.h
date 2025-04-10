// ---------------------------------------------------------------------
// SPDX-License-Identifier: GPL-3.0-or-later
// xdp_helper.h is a part of Blitzping.
// ---------------------------------------------------------------------

#pragma once
#ifndef XDP_HELPER_H
#define XDP_HELPER_H

#include <stdio.h>
#include <stdlib.h>  // For realpath()
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>  // For nice() and access()
#include <sys/resource.h>
#include <limits.h>  // For PATH_MAX

/**
 * Configure system resources for optimal XDP performance
 * 
 * @return true if successful, false otherwise
 */
static bool xdp_set_system_resources(void) {
    /* Increase memlock limit for UMEM allocation */
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) failed: %s\n", 
                strerror(errno));
        return false;
    }
    
    /* Set process priority using process priority functions */
    #if defined(_POSIX_C_SOURCE) && (_POSIX_C_SOURCE >= 200112L)
    {
        /* We need to explicitly declare nice() with a function prototype */
        extern int nice(int);
        
        errno = 0;
        int ret = nice(-20);
        if (ret == -1 && errno != 0) {
            fprintf(stderr, "WARNING: Failed to set process priority: %s\n",
                    strerror(errno));
        }
    }
    #else
    fprintf(stderr, "WARNING: Setting process priority not supported on this platform\n");
    #endif
    
    return true;
}

/**
 * Disable IRQ balancing if possible (for better performance)
 * 
 * @param ifname Interface name
 * @param queue_id Queue ID
 * @return true if successful, false otherwise
 */
static bool xdp_disable_irq_balance(const char *ifname, int queue_id) {
    /* Reduced command string size to avoid truncation warning */
    char cmd[512]; /* Increased buffer size from 256 to 512 */
    
    /* Fixed format string to avoid truncation */
    snprintf(cmd, sizeof(cmd),
             "if command -v ethtool >/dev/null && "
             "command -v grep >/dev/null && "
             "command -v awk >/dev/null; then "
             "irq=$(ethtool -l %s 2>/dev/null | grep -i \"rx-%d\" | "
             "awk '{print $1}'); "
             "if [ -n \"$irq\" ]; then "
             "echo 1 > /proc/irq/$irq/smp_affinity_list 2>/dev/null; "
             "fi; fi", 
             ifname, queue_id);
    
    /* Run the command but don't fail if unsuccessful */
    if (system(cmd) != 0) {
        fprintf(stderr, "WARNING: Could not set IRQ affinity\n");
        return false;
    }
    
    return true;
}

/**
 * Check if interface supports needed XDP features
 * 
 * @param ifname Interface name
 * @return true if supported, false otherwise
 */
static bool xdp_check_interface_support(const char *ifname) {
    /* Check if interface exists */
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/sys/class/net/%s", ifname);
    if (access(path, F_OK) != 0) {
        fprintf(stderr, "ERROR: Interface %s does not exist\n", ifname);
        return false;
    }
    
    /* Check driver type (optional) */
    snprintf(path, sizeof(path), "/sys/class/net/%s/device/driver", ifname);
    char driver[128] = {0};
    FILE *f = fopen(path, "r");
    if (f) {
        /* Manually read the symlink without using realpath */
        char link_path[PATH_MAX] = {0};
        ssize_t link_size = readlink(path, link_path, sizeof(link_path) - 1);
        if (link_size != -1) {
            /* Extract the last component of the path */
            char *last_slash = strrchr(link_path, '/');
            if (last_slash) {
                strncpy(driver, last_slash + 1, sizeof(driver) - 1);
            }
        }
        
        fclose(f);
    }
    
    if (driver[0]) {
        printf("Interface %s uses driver: %s\n", ifname, driver);
        
        /* Check if it's a known high-performance driver */
        const char *xdp_drivers[] = {
            "i40e", "ice", "mlx5", "ixgbe", "ixgbevf", "nfp", 
            "dpaa2", "qede", "bnxt", "tun", "virtio_net"
        };
        
        bool good_driver = false;
        for (size_t i = 0; i < sizeof(xdp_drivers)/sizeof(xdp_drivers[0]); i++) {
            if (strcmp(driver, xdp_drivers[i]) == 0) {
                good_driver = true;
                break;
            }
        }
        
        if (!good_driver) {
            printf("WARNING: Driver %s may not have optimal XDP performance\n", driver);
        } else {
            printf("Driver %s has good XDP support\n", driver);
        }
    }
    
    return true;
}

/* Helper function to improve system configuration for XDP */
static void xdp_optimize_system(const char *ifname, int queue_id) {
    /* Configure system resources */
    xdp_set_system_resources();
    
    /* Check interface compatibility */
    xdp_check_interface_support(ifname);
    
    /* Try to optimize IRQ settings */
    xdp_disable_irq_balance(ifname, queue_id);
    
    /* Report optimizations */
    printf("System optimized for XDP performance\n");
}

#endif // XDP_HELPER_H

// ---------------------------------------------------------------------
// END OF FILE: xdp_helper.h
// ---------------------------------------------------------------------
