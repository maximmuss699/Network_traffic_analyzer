// statistics.c

/**
 * Author: Maksim Samusevich
 * Login: xsamus00
 **/

#include "statistics.h"
#include <ncurses.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Function to compare connections by bytes (for sorting)
int compare_bytes(const void *a, const void *b) {
    const Connection *connA = (const Connection *)a;
    const Connection *connB = (const Connection *)b;
    uint64_t totalA = connA->rx_bytes + connA->tx_bytes;
    uint64_t totalB = connB->rx_bytes + connB->tx_bytes;
    if (totalA < totalB) return 1;
    if (totalA > totalB) return -1;
    return 0;
}

// Function to compare connections by packets (for sorting)
int compare_packets(const void *a, const void *b) {
    const Connection *connA = (const Connection *)a;
    const Connection *connB = (const Connection *)b;
    uint64_t totalA = connA->rx_packets + connA->tx_packets;
    uint64_t totalB = connB->rx_packets + connB->tx_packets;
    if (totalA < totalB) return 1;
    if (totalA > totalB) return -1;
    return 0;
}

// Function to display statistics
void display_statistics() {
    // Clear the screen
    clear();

    // Display headers
    mvprintw(0, 0, "Src IP:port                          Dst IP:port                     Proto             Rx         Tx");
    mvprintw(1, 0, "                                                                                                  B/s P/s     B/s P/s");

    // Sort connections
    if (sort_mode == 'b') {
        qsort(connections, connection_count, sizeof(Connection), compare_bytes);
        if (debug_mode)
            fprintf(log_file, "Connections sorted by bytes\n");
    } else {
        qsort(connections, connection_count, sizeof(Connection), compare_packets);
        if (debug_mode)
            fprintf(log_file, "Connections sorted by packets\n");
    }

    int displayed_connections = 0;

    // Display only the top-10 connections
    for (int i = 0; i < connection_count && displayed_connections < 10; i++) {
        // Skip inactive connections
        if (connections[i].rx_bytes == 0 && connections[i].tx_bytes == 0 &&
            connections[i].rx_packets == 0 && connections[i].tx_packets == 0) {
            continue; 
        }

        char src[1024], dst[1024], rx_bw[16], tx_bw[16];
        char rx_pps_str[16], tx_pps_str[16];
        char rx_pps_unit[4], tx_pps_unit[4]; 
        char rx_unit[4], tx_unit[4];

        int is_icmp = (strcmp(connections[i].protocol, "icmp") == 0 ||
                       strcmp(connections[i].protocol, "icmp6") == 0);

        // Check if any of the IP addresses is local
        int ip1_local = is_local_ip(connections[i].ip1);
        int ip2_local = is_local_ip(connections[i].ip2);
        int any_local = ip1_local || ip2_local;

        // Identify source and destination IP
        if (is_icmp) {
            if (any_local) {
                if (connections[i].last_direction == 1) { 
                    if (ip1_local) { // Tx: local -> remote
                        if (is_ipv6_address(connections[i].ip1)) {
                            snprintf(src, sizeof(src), "[%.45s]", connections[i].ip1);
                        } else {
                            snprintf(src, sizeof(src), "%.45s", connections[i].ip1);
                        }

                        if (is_ipv6_address(connections[i].ip2)) {
                            snprintf(dst, sizeof(dst), "[%.45s]", connections[i].ip2);
                        } else {
                            snprintf(dst, sizeof(dst), "%.45s", connections[i].ip2);
                        }
                    } else { // ip2_local
                        if (is_ipv6_address(connections[i].ip2)) {
                            snprintf(src, sizeof(src), "[%.45s]", connections[i].ip2);
                        } else {
                            snprintf(src, sizeof(src), "%.45s", connections[i].ip2);
                        }

                        if (is_ipv6_address(connections[i].ip1)) {
                            snprintf(dst, sizeof(dst), "[%.45s]", connections[i].ip1);
                        } else {
                            snprintf(dst, sizeof(dst), "%.45s", connections[i].ip1);
                        }
                    }
                } else { // Rx: remote -> local
                    if (ip2_local) {
                        // ip2 local, ip1 remote
                        if (is_ipv6_address(connections[i].ip1)) {
                            snprintf(src, sizeof(src), "[%.45s]", connections[i].ip1);
                        } else {
                            snprintf(src, sizeof(src), "%.45s", connections[i].ip1);
                        }

                        if (is_ipv6_address(connections[i].ip2)) {
                            snprintf(dst, sizeof(dst), "[%.45s]", connections[i].ip2);
                        } else {
                            snprintf(dst, sizeof(dst), "%.45s", connections[i].ip2);
                        }
                    } else { // ip1_local
                        // ip1 local, ip2 remote
                        if (is_ipv6_address(connections[i].ip2)) {
                            snprintf(src, sizeof(src), "[%.45s]", connections[i].ip2);
                        } else {
                            snprintf(src, sizeof(src), "%.45s", connections[i].ip2);
                        }

                        if (is_ipv6_address(connections[i].ip1)) {
                            snprintf(dst, sizeof(dst), "[%.45s]", connections[i].ip1);
                        } else {
                            snprintf(dst, sizeof(dst), "%.45s", connections[i].ip1);
                        }
                    }
                }
            } else {
                // If no local IPs are found, set src=ip1, dst=ip2
                if (is_ipv6_address(connections[i].ip1)) {
                    snprintf(src, sizeof(src), "[%.45s]", connections[i].ip1);
                } else {
                    snprintf(src, sizeof(src), "%.45s", connections[i].ip1);
                }

                if (is_ipv6_address(connections[i].ip2)) {
                    snprintf(dst, sizeof(dst), "[%s]", connections[i].ip2);
                } else {
                    snprintf(dst, sizeof(dst), "%.45s", connections[i].ip2);
                }

                if (debug_mode) {
                    fprintf(log_file, "No local IP found. Default direction set: %s -> %s\n", connections[i].ip1, connections[i].ip2);
                }
            }
        } else {
            // For non-ICMP connections
            if (any_local) {
                if (connections[i].last_direction == 1) { // Tx
                    if (ip1_local) {
                        // ip1 local -> ip2 remote
                        if (is_ipv6_address(connections[i].ip1)) {
                            snprintf(src, sizeof(src), "[%.45s]:%d", connections[i].ip1, connections[i].port1);
                        } else {
                            snprintf(src, sizeof(src), "%.45s:%d", connections[i].ip1, connections[i].port1);
                        }

                        if (is_ipv6_address(connections[i].ip2)) {
                            snprintf(dst, sizeof(dst), "[%.45s]:%d", connections[i].ip2, connections[i].port2);
                        } else {
                            snprintf(dst, sizeof(dst), "%.45s:%d", connections[i].ip2, connections[i].port2);
                        }
                    } else { 
                        // ip2 local -> ip1 remote
                        if (is_ipv6_address(connections[i].ip2)) {
                            snprintf(src, sizeof(src), "[%.45s]:%d", connections[i].ip2, connections[i].port2);
                        } else {
                            snprintf(src, sizeof(src), "%.45s:%d", connections[i].ip2, connections[i].port2);
                        }

                        if (is_ipv6_address(connections[i].ip1)) {
                            snprintf(dst, sizeof(dst), "[%.45s]:%d", connections[i].ip1, connections[i].port1);
                        } else {
                            snprintf(dst, sizeof(dst), "%.45s:%d", connections[i].ip1, connections[i].port1);
                        }
                    }
                } else { // Rx: remote -> local
                    if (ip2_local) {
                        // ip2 local -> ip1 remote
                        if (is_ipv6_address(connections[i].ip2)) {
                            snprintf(src, sizeof(src), "[%.45s]:%d", connections[i].ip1, connections[i].port1);
                        } else {
                            snprintf(src, sizeof(src), "%.45s:%d", connections[i].ip1, connections[i].port1);
                        }

                        if (is_ipv6_address(connections[i].ip1)) {
                            snprintf(dst, sizeof(dst), "[%.45s]:%d", connections[i].ip2, connections[i].port2);
                        } else {
                            snprintf(dst, sizeof(dst), "%.45s:%d", connections[i].ip2, connections[i].port2);
                        }
                    } else { 
                        // ip1 local -> ip2 remote
                        if (is_ipv6_address(connections[i].ip1)) {
                            snprintf(src, sizeof(src), "[%.45s]:%d", connections[i].ip2, connections[i].port2);
                        } else {
                            snprintf(src, sizeof(src), "%.45s:%d", connections[i].ip2, connections[i].port2);
                        }

                        if (is_ipv6_address(connections[i].ip2)) {
                            snprintf(dst, sizeof(dst), "[%.45s]:%d", connections[i].ip1, connections[i].port1);
                        } else {
                            snprintf(dst, sizeof(dst), "%.45s:%d", connections[i].ip1, connections[i].port1);
                        }
                    }
                }
            } else {
                // If no local IPs are found, set src=ip1, dst=ip2
                if (is_ipv6_address(connections[i].ip1)) {
                    snprintf(src, sizeof(src), "[%.45s]:%d", connections[i].ip1, connections[i].port1);
                } else {
                    snprintf(src, sizeof(src), "%.45s:%d", connections[i].ip1, connections[i].port1);
                }

                if (is_ipv6_address(connections[i].ip2)) {
                    snprintf(dst, sizeof(dst), "[%.45s]:%d", connections[i].ip2, connections[i].port2);
                } else {
                    snprintf(dst, sizeof(dst), "%.45s:%d", connections[i].ip2, connections[i].port2);
                }

                if (debug_mode) {
                    fprintf(log_file, "No local IP found. Default direction set: %s:%d -> %s:%d\n",
                            connections[i].ip1, connections[i].port1,
                            connections[i].ip2, connections[i].port2);
                }
            }
        }

        // Log the last direction of the connection
        if (debug_mode) {
            fprintf(log_file, "Last direction of [%d] connection: %d\n", i, connections[i].last_direction);
        }

        double time_diff = (double)interval;
        if (time_diff == 0) time_diff = 1.0;

        // Format the receive and transmit bandwidth
        format_bandwidth(connections[i].rx_bytes, time_diff, rx_bw, rx_unit);
        format_bandwidth(connections[i].tx_bytes, time_diff, tx_bw, tx_unit);

        // Format packets per second
        format_value(connections[i].rx_packets / time_diff, rx_pps_str, rx_pps_unit);
        format_value(connections[i].tx_packets / time_diff, tx_pps_str, tx_pps_unit);

        // Display the connection statistics
        mvprintw(displayed_connections + 2, 0, "%-35s %-30s %-7s %6s %-2s %6s %-2s %6s %-2s %6s %-2s",
         src, dst, connections[i].protocol,
         rx_bw, rx_unit, rx_pps_str, rx_pps_unit,
         tx_bw, tx_unit, tx_pps_str, tx_pps_unit);

         

        if (debug_mode) {
            fprintf(log_file, "Connection %d: %s -> %s, Protocol: %s, Rx: %s%s (%s p/s), Tx: %s%s (%s p/s)\n",
                    i, src, dst, connections[i].protocol,
                    rx_bw, rx_unit, rx_pps_str,
                    tx_bw, tx_unit, tx_pps_str);
        }

        // Reset the connection statistics
        connections[i].rx_bytes = 0;
        connections[i].tx_bytes = 0;
        connections[i].rx_packets = 0;
        connections[i].tx_packets = 0;

        displayed_connections++;
    }

    // Refresh the screen
    refresh();
}
