// utils.c

/**
 * Author: Maksim Samusevich
 * Login: xsamus00
 **/

#include "isa-top.h"
#include <time.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

// 
char local_ips[MAX_IP_ADDRESSES][INET6_ADDRSTRLEN];
int local_ip_count = 0;

// Sleep function to reduce CPU usage
void sleep_ms(long milliseconds) {
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

// Get local IP addresses for the specified interface
void get_local_ips(char *interface) {
    struct ifaddrs *ifaddr, *ifa;
    int family;
    char host[INET6_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    local_ip_count = 0;

    for (ifa = ifaddr; ifa != NULL && local_ip_count < MAX_IP_ADDRESSES; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (strcmp(ifa->ifa_name, interface) != 0)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET || family == AF_INET6) {
            int s = getnameinfo(ifa->ifa_addr,
                                (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                                host, sizeof(host),
                                NULL, 0, NI_NUMERICHOST);
            if (s == 0) {
                strcpy(local_ips[local_ip_count], host);
                if (debug_mode)
                    fprintf(log_file, "Local IP address (%s): %s\n", interface, host);
                local_ip_count++;
            } else {
                fprintf(stderr, "getnameinfo() failed: %s\n", gai_strerror(s));
            }
        }
    }

    freeifaddrs(ifaddr);
}

// Check if the IP address is local
int is_local_ip(char *ip) {
    char ip_copy[INET6_ADDRSTRLEN];
    char packet_ip_copy[INET6_ADDRSTRLEN];

    for (int i = 0; i < local_ip_count; i++) {
        // Copy local IP and remove scope ID if present
        snprintf(ip_copy, sizeof(ip_copy), "%s", local_ips[i]);
        char *percent = strchr(ip_copy, '%');
        if (percent) {
            *percent = '\0';
        }

        // Copy packet IP and remove scope ID if present
        snprintf(packet_ip_copy, sizeof(packet_ip_copy), "%s", ip);
        percent = strchr(packet_ip_copy, '%');
        if (percent) {
            *percent = '\0';
        }

        if (strcmp(ip_copy, packet_ip_copy) == 0) {
            return 1;
        }
    }
    return 0;
}

// Check if the IP address is IPv6
int is_ipv6_address(const char *ip) {
    return strchr(ip, ':') != NULL;
}

// Format a value with a unit
void format_value(double value, char *output, char *unit_str) {
    const char *units[] = {"", "k", "M", "G"};
    int unit = 0;
    while (value >= 1000 && unit < 3) {
        value /= 1000;
        unit++;
    }
    strcpy(unit_str, units[unit]);
    snprintf(output, 16, "%.1f", value);
}

// Format bandwidth in bits per second
void format_bandwidth(double bytes, double interval, char *output, char *unit_str) {
    double bps = (bytes * 8) / interval; // Convert bytes to bits
    const char *units[] = {"b", "k", "M", "G"}; 
    int unit = 0;
    while (bps >= 1000 && unit < 3) {
        bps /= 1000;
        unit++;
    }
    strcpy(unit_str, units[unit]);
    snprintf(output, 16, "%.1f", bps);
}

// Function to print usage
void print_usage() {
    fprintf(stderr, "Usage: isa-top -i <interface> [-s b|p] [-t interval] [-d]\n");
    fprintf(stderr, "  -i <interface> : Specify the network interface to monitor (required)\n");
    fprintf(stderr, "  -s b|p         : Sort mode: 'b' for bytes, 'p' for packets (default 'b')\n");
    fprintf(stderr, "  -t interval    : Interval for updating statistics in seconds (default 1)\n");
    fprintf(stderr, "  -d             : Enable debug mode\n");
}

// Function to parse command line arguments
int parse_arguments(int argc, char *argv[]) {
    int opt;
    interface = NULL;
    sort_mode = 'b';
    interval = 1;

    while ((opt = getopt(argc, argv, "i:s:t:d")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 's':
                if (optarg[0] == 'b' || optarg[0] == 'p') {
                    sort_mode = optarg[0];
                } else {
                    fprintf(stderr, "Invalid sort mode: %c\n", optarg[0]);
                    return -1;
                }
                break;
            case 't':
                interval = atoi(optarg);
                if (interval <= 0) {
                    fprintf(stderr, "Interval must be a positive number\n");
                    return -1;
                }
                break;
            case 'd':
                debug_mode = 1;
                break;
            default:
                print_usage();
                return -1;
        }
    }

    if (interface == NULL) {
        fprintf(stderr, "Error: Network interface not specified\n");
        print_usage();
        return -1;
    }

    return 0;
}