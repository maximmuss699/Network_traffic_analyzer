/**
 * Author: Maksim Samusevich
 * Login: xsamus00
 **/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>       
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <ncurses.h>
#include <signal.h>
#include <time.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/time.h>

#if defined(__APPLE__) || defined(__MACH__)
// macOS
#define TCP_SRC_PORT(th) ((th)->th_sport)
#define TCP_DST_PORT(th) ((th)->th_dport)
#define UDP_SRC_PORT(uh) ((uh)->uh_sport)
#define UDP_DST_PORT(uh) ((uh)->uh_dport)
#else
// Linux and others
#define TCP_SRC_PORT(th) ((th)->source)
#define TCP_DST_PORT(th) ((th)->dest)
#define UDP_SRC_PORT(uh) ((uh)->source)
#define UDP_DST_PORT(uh) ((uh)->dest)
#endif

#define MAX_CONNECTIONS 1000
#define MAX_IP_ADDRESSES 10

char local_ips[MAX_IP_ADDRESSES][INET6_ADDRSTRLEN];
int local_ip_count = 0;

typedef struct {
    char ip1[INET6_ADDRSTRLEN];
    char ip2[INET6_ADDRSTRLEN];
    uint16_t port1;
    uint16_t port2;
    char protocol[8];
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t tx_packets;
} Connection;

// Sleep function to reduce CPU usage
void sleep_ms(long milliseconds) {
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

Connection connections[MAX_CONNECTIONS];
int connection_count = 0;

// Global variables for settings
char *interface = NULL;
char sort_mode = 'b';
int interval = 1;
int debug_mode = 0;

// Global variables for pcap
int linktype = -1;

volatile sig_atomic_t stop = 0;

pcap_t *handle = NULL;

// Variable for log file
FILE *log_file = NULL;

// Structure for storing settings
typedef struct {
    char *interface;
    char sort_mode;
    int interval;
} Settings;

// Prototype for argument parsing function
int parse_arguments(int argc, char *argv[], Settings *settings);

// Function to print usage information
void print_usage() {
    fprintf(stderr, "Usage: isa-top -i <interface> [-s b|p] [-t interval] [-d]\n");
    fprintf(stderr, "  -i <interface> : Specify the network interface to monitor (required)\n");
    fprintf(stderr, "  -s b|p         : Sort mode: 'b' for bytes, 'p' for packets (default 'b')\n");
    fprintf(stderr, "  -t interval    : Interval for updating statistics in seconds (default 1)\n");
    fprintf(stderr, "  -d             : Enable debug mode\n");
}

// SIGINT signal handler
void handle_sigint() {
    pcap_breakloop(handle);
    stop = 1;
}

// Retrieve local IP addresses of the specified interface
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

        // Check only the specified interface
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

// Check if the IP is local
int is_local_ip(char *ip) {
    char ip_copy[INET6_ADDRSTRLEN];
    char packet_ip_copy[INET6_ADDRSTRLEN];

    for (int i = 0; i < local_ip_count; i++) {
        // Copy local IP and remove scope identifier if present
        snprintf(ip_copy, sizeof(ip_copy), "%s", local_ips[i]);
        char *percent = strchr(ip_copy, '%');
        if (percent) {
            *percent = '\0';
        }

        // Copy packet IP and remove scope identifier if present
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

// Structure for creating a unique connection key
typedef struct {
    char ip1[INET6_ADDRSTRLEN];
    char ip2[INET6_ADDRSTRLEN];
    uint16_t port1;
    uint16_t port2;
    char protocol[8];
} ConnectionKey;

// Compare two connection keys (direction-independent)
int compare_keys(ConnectionKey *key1, ConnectionKey *key2) {
    // Compare ip1 and ip2 in both directions
    if (strcmp(key1->ip1, key2->ip1) == 0 &&
        strcmp(key1->ip2, key2->ip2) == 0 &&
        key1->port1 == key2->port1 &&
        key1->port2 == key2->port2 &&
        strcmp(key1->protocol, key2->protocol) == 0) {
        return 1;
    }

    if (strcmp(key1->ip1, key2->ip2) == 0 &&
        strcmp(key1->ip2, key2->ip1) == 0 &&
        key1->port1 == key2->port2 &&
        key1->port2 == key2->port1 &&
        strcmp(key1->protocol, key2->protocol) == 0) {
        return 1;
    }

    return 0;
}

// Find existing connection regardless of direction
int find_connection(ConnectionKey *key) {
    for (int i = 0; i < connection_count; i++) {
        ConnectionKey existing_key;
        strcpy(existing_key.ip1, connections[i].ip1);
        strcpy(existing_key.ip2, connections[i].ip2);
        existing_key.port1 = connections[i].port1;
        existing_key.port2 = connections[i].port2;
        strcpy(existing_key.protocol, connections[i].protocol);

        if (compare_keys(&existing_key, key)) {
            return i;
        }
    }
    // New connection
    return -1;
}

// Update connection statistics
void update_connection(char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port,
                      char *protocol, uint32_t bytes, int direction) {
    ConnectionKey key;

    // Order IPs and ports for consistency
    if (strcmp(src_ip, dst_ip) < 0 || (strcmp(src_ip, dst_ip) == 0 && src_port <= dst_port)) {
        strcpy(key.ip1, src_ip);
        strcpy(key.ip2, dst_ip);
        key.port1 = src_port;
        key.port2 = dst_port;
    } else {
        strcpy(key.ip1, dst_ip);
        strcpy(key.ip2, src_ip);
        key.port1 = dst_port;
        key.port2 = src_port;
    }

    strcpy(key.protocol, protocol);


    int index = find_connection(&key);
    if (index == -1) {
        if (connection_count < MAX_CONNECTIONS) {
            index = connection_count++;
            strcpy(connections[index].ip1, key.ip1);
            strcpy(connections[index].ip2, key.ip2);
            connections[index].port1 = key.port1;
            connections[index].port2 = key.port2;
            strcpy(connections[index].protocol, key.protocol);
            connections[index].rx_bytes = 0;
            connections[index].tx_bytes = 0;
            connections[index].rx_packets = 0;
            connections[index].tx_packets = 0;
            if (debug_mode)
                fprintf(log_file, "Added new connection: %s:%d <-> %s:%d (%s)\n",
                        key.ip1, key.port1, key.ip2, key.port2, key.protocol);
        } else {
            if (debug_mode)
                fprintf(log_file, "Exceeded maximum number of connections (%d)\n", MAX_CONNECTIONS);
            return;
        }
    }

    if (direction == 0) { // Receive (Rx)
        connections[index].rx_bytes += bytes;
        connections[index].rx_packets += 1;
    } else { // Transmit (Tx)
        connections[index].tx_bytes += bytes;
        connections[index].tx_packets += 1;
    }
}

// Format a value with units
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

// Modified function to display bandwidth in bits per second
void format_bandwidth(double bytes, double interval, char *output, char *unit_str) {
    double bps = (bytes * 8) / interval; // Convert bytes to bits
    const char *units[] = {"b", "k", "M", "G"}; // Bits per second
    int unit = 0;
    while (bps >= 1000 && unit < 3) {
        bps /= 1000;
        unit++;
    }
    strcpy(unit_str, units[unit]);
    snprintf(output, 16, "%.1f", bps);
}

// Compare by total bytes
int compare_bytes(const void *a, const void *b) {
    Connection *connA = (Connection *)a;
    Connection *connB = (Connection *)b;
    uint64_t totalA = connA->rx_bytes + connA->tx_bytes;
    uint64_t totalB = connB->rx_bytes + connB->tx_bytes;
    if (totalA < totalB) return 1;
    if (totalA > totalB) return -1;
    return 0;
}

// Compare by total packets
int compare_packets(const void *a, const void *b) {
    Connection *connA = (Connection *)a;
    Connection *connB = (Connection *)b;
    uint64_t totalA = connA->rx_packets + connA->tx_packets;
    uint64_t totalB = connB->rx_packets + connB->tx_packets;
    if (totalA < totalB) return 1;
    if (totalA > totalB) return -1;
    return 0;
}

int is_ipv6_address(const char *ip) {
    return strchr(ip, ':') != NULL;
}

// Display statistics
void display_statistics() {
    // Clear the screen
    clear();

    // Print headers
    mvprintw(0, 0, "Src IP:port                         Dst IP:port                      Proto   Rx        Tx");
    mvprintw(1, 0, "                                                                               bps p/s     bps p/s");

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

    // Display top 10 connections
    for (int i = 0; i < connection_count && i < 10; i++) {
        char src[100], dst[100], rx_bw[16], tx_bw[16];
        char rx_pps_str[16], tx_pps_str[16];
        char rx_unit[4], tx_unit[4], rx_pps_unit[4], tx_pps_unit[4];

        // Format source and destination IP:port
        snprintf(src, sizeof(src), "%s:%d", connections[i].ip1, connections[i].port1);
        snprintf(dst, sizeof(dst), "%s:%d", connections[i].ip2, connections[i].port2);

        double time_diff = (double)interval;
        if (time_diff == 0) time_diff = 1.0;

        // Format bandwidth in bits per second
        format_bandwidth(connections[i].rx_bytes, time_diff, rx_bw, rx_unit);
        format_bandwidth(connections[i].tx_bytes, time_diff, tx_bw, tx_unit);

        // Calculate packets per second
        double rx_pps = connections[i].rx_packets / time_diff;
        double tx_pps = connections[i].tx_packets / time_diff;

        // Format packets per second
        format_value(rx_pps, rx_pps_str, rx_pps_unit);
        format_value(tx_pps, tx_pps_str, tx_pps_unit);

        // Format the output string with alignment and units
        mvprintw(i + 2, 0, "%-32s %-32s %-6s %6s%-2s %4s%-1s %6s%-2s %4s%-1s",
                 src, dst, connections[i].protocol,
                 rx_bw, rx_unit, rx_pps_str, rx_pps_unit,
                 tx_bw, tx_unit, tx_pps_str, tx_pps_unit);

        if (debug_mode) {
            fprintf(log_file, "Connection %d: %s <-> %s, Protocol: %s, Rx: %s%s (%s%s p/s), Tx: %s%s (%s%s p/s)\n",
                    i, src, dst, connections[i].protocol,
                    rx_bw, rx_unit, rx_pps_str, rx_pps_unit,
                    tx_bw, tx_unit, tx_pps_str, tx_pps_unit);
        }

        // Reset counters after displaying
        connections[i].rx_bytes = 0;
        connections[i].tx_bytes = 0;
        connections[i].rx_packets = 0;
        connections[i].tx_packets = 0;
    }

    // Refresh the screen
    refresh();
}

// Packet handler for captured packets
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (debug_mode)
        fprintf(log_file, "Captured packet length %u bytes\n", header->len);

     (void)args; // Unused 

    if (linktype == DLT_EN10MB) { // Ethernet
        int ethernet_header_length = 14; // Standard Ethernet header length
        if ((int)header->len < ethernet_header_length) {
            // Packet too short for Ethernet header
            return;
        }

        uint16_t eth_type = ntohs(*(uint16_t*)(packet + 12));

        if (eth_type == 0x0800) { // IPv4
            if (header->len < ethernet_header_length + sizeof(struct ip)) {
                // Packet too short for IPv4 header
                return;
            }

            struct ip *ip_hdr = (struct ip*)(packet + ethernet_header_length);
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

            // Determine packet direction
            int direction;
            if (is_local_ip(src_ip)) {
                direction = 1; // Outgoing
            } else if (is_local_ip(dst_ip)) {
                direction = 0; // Incoming
            } else {
                // Packet not related to our host
                return;
            }

            uint8_t protocol = ip_hdr->ip_p;
            uint16_t src_port = 0;
            uint16_t dst_port = 0;
            char proto_str[8] = "other";

            const u_char *transport_header = packet + ethernet_header_length + (ip_hdr->ip_hl * 4);

            if (protocol == IPPROTO_TCP) {
                if (header->len < ethernet_header_length + (ip_hdr->ip_hl * 4) + sizeof(struct tcphdr)) {
                    // Packet too short for TCP header
                    return;
                }
                struct tcphdr *tcp_hdr = (struct tcphdr*)transport_header;
                src_port = ntohs(TCP_SRC_PORT(tcp_hdr));
                dst_port = ntohs(TCP_DST_PORT(tcp_hdr));
                strcpy(proto_str, "tcp");
            }
            else if (protocol == IPPROTO_UDP) {
                if (header->len < ethernet_header_length + (ip_hdr->ip_hl * 4) + sizeof(struct udphdr)) {
                    // Packet too short for UDP header
                    return;
                }
                struct udphdr *udp_hdr = (struct udphdr*)transport_header;
                src_port = ntohs(UDP_SRC_PORT(udp_hdr));
                dst_port = ntohs(UDP_DST_PORT(udp_hdr));
                strcpy(proto_str, "udp");
            }
            else if (protocol == IPPROTO_ICMP) {
                strcpy(proto_str, "icmp");
            }

            update_connection(src_ip, dst_ip, src_port, dst_port, proto_str, header->len - ethernet_header_length, direction);
        }
        else if (eth_type == 0x86DD) { // IPv6
            if (header->len < ethernet_header_length + sizeof(struct ip6_hdr)) {
                // Packet too short for IPv6 header
                return;
            }

            struct ip6_hdr *ip6_hdr = (struct ip6_hdr*)(packet + ethernet_header_length);
            char src_ip[INET6_ADDRSTRLEN];
            char dst_ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

            // Determine packet direction
            int direction;
            if (is_local_ip(src_ip)) {
                direction = 1; // Outgoing
            }
            else if (is_local_ip(dst_ip)) {
                direction = 0; // Incoming
            }
            else {
                // Packet not related to our host
                return;
            }

            uint8_t next_header = ip6_hdr->ip6_nxt;
            uint16_t src_port = 0;
            uint16_t dst_port = 0;
            char proto_str[8] = "other";

            const u_char *transport_header = packet + ethernet_header_length + sizeof(struct ip6_hdr);

            if (next_header == IPPROTO_TCP) {
                if (header->len < ethernet_header_length + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)) {
                    // Packet too short for TCP header
                    return;
                }
                struct tcphdr *tcp_hdr = (struct tcphdr*)transport_header;
                src_port = ntohs(TCP_SRC_PORT(tcp_hdr));
                dst_port = ntohs(TCP_DST_PORT(tcp_hdr));
                strcpy(proto_str, "tcp");
            }
            else if (next_header == IPPROTO_UDP) {
                if (header->len < ethernet_header_length + sizeof(struct ip6_hdr) + sizeof(struct udphdr)) {
                    // Packet too short for UDP header
                    return;
                }
                struct udphdr *udp_hdr = (struct udphdr*)transport_header;
                src_port = ntohs(UDP_SRC_PORT(udp_hdr));
                dst_port = ntohs(UDP_DST_PORT(udp_hdr));
                strcpy(proto_str, "udp");
            }
            else if (next_header == IPPROTO_ICMPV6) {
                strcpy(proto_str, "icmp6");
            }

            update_connection(src_ip, dst_ip, src_port, dst_port, proto_str, header->len - ethernet_header_length, direction);
        }
    }
    else if (linktype == DLT_NULL) { // Loopback (e.g., lo0 on macOS)
        if (header->len < 4) {
            // Packet too short for DLT_NULL header
            return;
        }

        uint32_t af = *(uint32_t*)packet;

        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        char protocol[8] = "other";
        uint16_t src_port = 0, dst_port = 0;

        const u_char *ip_packet = packet + 4;

        if (af == AF_INET) { // IPv4
            if (header->len < 4 + sizeof(struct ip)) {
                // Packet too short for IPv4 header
                return;
            }

            struct ip *ip_hdr = (struct ip*)ip_packet;
            inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

            // Determine packet direction
            int direction;
            if (is_local_ip(src_ip)) {
                direction = 1; // Outgoing
            }
            else if (is_local_ip(dst_ip)) {
                direction = 0; // Incoming
            }
            else {
                // Packet not related to our host
                return;
            }

            uint8_t protocol_num = ip_hdr->ip_p;

            const u_char *transport_header = ip_packet + (ip_hdr->ip_hl * 4);

            if (protocol_num == IPPROTO_TCP) {
                if (header->len < 4 + (ip_hdr->ip_hl * 4) + sizeof(struct tcphdr)) {
                    // Packet too short for TCP header
                    return;
                }
                struct tcphdr *tcp_hdr = (struct tcphdr*)transport_header;
                src_port = ntohs(TCP_SRC_PORT(tcp_hdr));
                dst_port = ntohs(TCP_DST_PORT(tcp_hdr));
                strcpy(protocol, "tcp");
            }
            else if (protocol_num == IPPROTO_UDP) {
                if (header->len < 4 + (ip_hdr->ip_hl * 4) + sizeof(struct udphdr)) {
                    // Packet too short for UDP header
                    return;
                }
                struct udphdr *udp_hdr = (struct udphdr*)transport_header;
                src_port = ntohs(UDP_SRC_PORT(udp_hdr));
                dst_port = ntohs(UDP_DST_PORT(udp_hdr));
                strcpy(protocol, "udp");
            }
            else if (protocol_num == IPPROTO_ICMP) {
                strcpy(protocol, "icmp");
            }
            else {
                strcpy(protocol, "other");
            }

            update_connection(src_ip, dst_ip, src_port, dst_port, protocol, header->len - 4, direction);
        }
        else if (af == AF_INET6) { // IPv6
            if (header->len < 4 + sizeof(struct ip6_hdr)) {
                // Packet too short for IPv6 header
                return;
            }

            struct ip6_hdr *ip6_hdr = (struct ip6_hdr*)ip_packet;
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

            // Determine packet direction
            int direction;
            if (is_local_ip(src_ip)) {
                direction = 1; // Outgoing
            }
            else if (is_local_ip(dst_ip)) {
                direction = 0; // Incoming
            }
            else {
                // Packet not related to our host
                return;
            }

            uint8_t next_header = ip6_hdr->ip6_nxt;
            uint16_t src_port = 0;
            uint16_t dst_port = 0;
            char proto_str[8] = "other";

            const u_char *transport_header = ip_packet + sizeof(struct ip6_hdr);

            if (next_header == IPPROTO_TCP) {
                if (header->len < 4 + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)) {
                    // Packet too short for TCP header
                    return;
                }
                struct tcphdr *tcp_hdr = (struct tcphdr*)transport_header;
                src_port = ntohs(TCP_SRC_PORT(tcp_hdr));
                dst_port = ntohs(TCP_DST_PORT(tcp_hdr));
                strcpy(proto_str, "tcp");
            }
            else if (next_header == IPPROTO_UDP) {
                if (header->len < 4 + sizeof(struct ip6_hdr) + sizeof(struct udphdr)) {
                    // Packet too short for UDP header
                    return;
                }
                struct udphdr *udp_hdr = (struct udphdr*)transport_header;
                src_port = ntohs(UDP_SRC_PORT(udp_hdr));
                dst_port = ntohs(UDP_DST_PORT(udp_hdr));
                strcpy(proto_str, "udp");
            }
            else if (next_header == IPPROTO_ICMPV6) {
                strcpy(proto_str, "icmp6");
            }

            update_connection(src_ip, dst_ip, src_port, dst_port, proto_str, header->len - 4, direction);
        }
        else {
            // Unknown address family
            return;
        }
    }
}

// Function to parse command-line arguments
int parse_arguments(int argc, char *argv[], Settings *settings) {
    int opt;
    // Initialize default values
    settings->interface = NULL;
    settings->sort_mode = 'b';
    settings->interval = 1;

    while ((opt = getopt(argc, argv, "i:s:t:d")) != -1) {
        switch (opt) {
            case 'i':
                settings->interface = optarg;
                break;
            case 's':
                if (optarg[0] == 'b' || optarg[0] == 'p') {
                    settings->sort_mode = optarg[0];
                } else {
                    fprintf(stderr, "Invalid sort mode: %c\n", optarg[0]);
                    return -1;
                }
                break;
            case 't':
                settings->interval = atoi(optarg);
                if (settings->interval <= 0) {
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

    // Check required parameter
    if (settings->interface == NULL) {
        fprintf(stderr, "Error: Network interface not specified\n");
        print_usage();
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    Settings settings;
    if (parse_arguments(argc, argv, &settings) != 0) {
        exit(EXIT_FAILURE);
    }

    // Set global variables based on settings
    interface = settings.interface;
    sort_mode = settings.sort_mode;
    interval = settings.interval;

    // Open log file
    log_file = fopen("isa-top.log", "w");
    if (log_file == NULL) {
        perror("Failed to open isa-top.log for logging");
        exit(EXIT_FAILURE);
    }

    // Set SIGINT handler
    signal(SIGINT, handle_sigint);

    // Retrieve local IP addresses
    get_local_ips(interface);

    // Initialize pcap
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        endwin();
        fprintf(stderr, "Failed to open device %s: %s\n", interface, errbuf);
        fclose(log_file);
        return EXIT_FAILURE;
    }

    // Set non-blocking mode for pcap
    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        endwin();
        fprintf(stderr, "Error setting non-blocking mode: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        fclose(log_file);
        return EXIT_FAILURE;
    }

    // Determine the link layer type
    linktype = pcap_datalink(handle);

    // Initialize ncurses
    initscr();
    cbreak();
    noecho();
    curs_set(FALSE);

    // Initialize time tracking variables
    struct timeval last_time, current_time;
    gettimeofday(&last_time, NULL);

    while (!stop) {
        // Check if interval has passed
        gettimeofday(&current_time, NULL);
        double elapsed = (current_time.tv_sec - last_time.tv_sec) + (current_time.tv_usec - last_time.tv_usec) / 1e6;
        if (elapsed >= interval) {
            display_statistics();
            last_time = current_time;
        }

        // Capture next packet (non-blocking)
        struct pcap_pkthdr *header;
        const u_char *packet;
        int ret = pcap_next_ex(handle, &header, &packet);
        if (ret == 1) {
            packet_handler(NULL, header, packet);
        } else if (ret == 0) {
            // No packets in buffer, sleep a bit
            if (debug_mode)
                fprintf(log_file, "No packets in buffer\n");
            sleep_ms(1);
        } else if (ret == -1) {
            fprintf(stderr, "Error capturing packets: %s\n", pcap_geterr(handle));
            break;
        } else if (ret == -2) {
            // pcap_breakloop() was called
            break;
        }
    }

    // Cleanup
    pcap_close(handle);
    endwin();
    fclose(log_file);
    return EXIT_SUCCESS;
}
