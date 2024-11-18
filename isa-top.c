
// isa-top.c

/**
 * Author: Maksim Samusevich
 * Login: xsamus00
 **/

#include "isa-top.h"
#include "utils.h"

// Array of connections
Connection connections[MAX_CONNECTIONS];
int connection_count = 0;

// Command line arguments
char *interface = NULL;
char sort_mode = 'b';
int interval = 1;
int debug_mode = 0;

// pcap variables
int linktype = -1;
pcap_t *handle = NULL;

// Log file
FILE *log_file = NULL;

volatile sig_atomic_t stop = 0;

// Signal handler for SIGINT
void handle_sigint() {
    pcap_breakloop(handle);
    stop = 1;
}



// Main function
int main(int argc, char *argv[]) {
    if (parse_arguments(argc, argv) != 0) {
        exit(EXIT_FAILURE);
    }

    // Open log file if debug mode is enabled
    if (debug_mode) {
        log_file = fopen("isa-top.log", "w");
        if (log_file == NULL) {
            perror("Failed to open isa-top.log for logging");
            exit(EXIT_FAILURE);
        }
    }

   
    signal(SIGINT, handle_sigint);

    // Get local IP addresses for the specified interface
    get_local_ips(interface);

    // Initialize pcap
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Failed to open device %s: %s\n", interface, errbuf);
        if (debug_mode) fclose(log_file);
        return EXIT_FAILURE;
    }

    // Set non-blocking mode
    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        fprintf(stderr, "Error setting non-blocking mode: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        if (debug_mode) fclose(log_file);
        return EXIT_FAILURE;
    }

    // Get link type
    linktype = pcap_datalink(handle);

    // ncurses initialization
    initscr();
    cbreak();
    noecho();
    curs_set(FALSE);

    struct timeval last_time, current_time;
    gettimeofday(&last_time, NULL);

    while (!stop) {
        // Check if it's time to display statistics
        gettimeofday(&current_time, NULL);
        double elapsed = (current_time.tv_sec - last_time.tv_sec) + (current_time.tv_usec - last_time.tv_usec) / 1e6;
        if (elapsed >= interval) {
            display_statistics();
            last_time = current_time;
        }

        // Capture packets
        struct pcap_pkthdr *header;
        const u_char *packet;
        int ret = pcap_next_ex(handle, &header, &packet);
        if (ret == 1) {
            packet_handler(NULL, header, packet);
        } else if (ret == 0) {
            // No packets in buffer
            if (debug_mode)
              //  fprintf(log_file, "No packets in buffer\n");
            sleep_ms(1);
        } else if (ret == -1) {
            fprintf(stderr, "Error capturing packets: %s\n", pcap_geterr(handle));
            break;
        } else if (ret == -2) {
            // Break loop
            break;
        }
    }

    // Cleanup
    pcap_close(handle);
    endwin();
    if (debug_mode) fclose(log_file);
    return EXIT_SUCCESS;
}

// Packet handler function
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (debug_mode)
        fprintf(log_file, "Captured packet length %u bytes\n", header->len);

    (void)args; // Unused here

    if (linktype == DLT_EN10MB) { // Ethernet
        int ethernet_header_length = 14;
        if ((int)header->len < ethernet_header_length) {
            // Packet is too short for Ethernet header
            return;
        }

        uint16_t eth_type = ntohs(*(uint16_t*)(packet + 12));

        if (eth_type == 0x0800) { // IPv4
            if (header->len < ethernet_header_length + sizeof(struct ip)) {
                // Packet is too short for IPv4 header
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
                direction = 1; 
            } else if (is_local_ip(dst_ip)) {
                direction = 0; 
            } else {
                if (debug_mode) {
                fprintf(log_file, "No local IP found. Default direction set: %s -> %s\n", src_ip, dst_ip);
                 }
                direction = 1;
            }

            uint8_t protocol = ip_hdr->ip_p;
            uint16_t src_port = 0;
            uint16_t dst_port = 0;
            char proto_str[8] = "other";

            const u_char *transport_header = packet + ethernet_header_length + (ip_hdr->ip_hl * 4);

            if (protocol == IPPROTO_TCP) {
                if (header->len < ethernet_header_length + (ip_hdr->ip_hl * 4) + sizeof(struct tcphdr)) {
                    // Packet is too short for TCP header
                    return;
                }
                struct tcphdr *tcp_hdr = (struct tcphdr*)transport_header;
                src_port = ntohs(TCP_SRC_PORT(tcp_hdr));
                dst_port = ntohs(TCP_DST_PORT(tcp_hdr));
                strcpy(proto_str, "tcp");
            }
            else if (protocol == IPPROTO_UDP) {
                if (header->len < ethernet_header_length + (ip_hdr->ip_hl * 4) + sizeof(struct udphdr)) {
                    // Packet is too short for UDP header
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
                // Packet is too short for IPv6 header
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
                direction = 1; 
            }
            else if (is_local_ip(dst_ip)) {
                direction = 0; 
            }
            else {
                if (debug_mode) {
                fprintf(log_file, "No local IP found. Default direction set: %s -> %s\n", src_ip, dst_ip);
                 }
                direction = 1;
            }

            uint8_t next_header = ip6_hdr->ip6_nxt;
            uint16_t src_port = 0;
            uint16_t dst_port = 0;
            char proto_str[8] = "other";

            const u_char *transport_header = packet + ethernet_header_length + sizeof(struct ip6_hdr);

            if (next_header == IPPROTO_TCP) {
                if (header->len < ethernet_header_length + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)) {
                    // Packet is too short for TCP header
                    return;
                }
                struct tcphdr *tcp_hdr = (struct tcphdr*)transport_header;
                src_port = ntohs(TCP_SRC_PORT(tcp_hdr));
                dst_port = ntohs(TCP_DST_PORT(tcp_hdr));
                strcpy(proto_str, "tcp");
            }
            else if (next_header == IPPROTO_UDP) {
                if (header->len < ethernet_header_length + sizeof(struct ip6_hdr) + sizeof(struct udphdr)) {
                    // Packet is too short for UDP header
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
    else if (linktype == DLT_NULL) { // Loopback 
        if (header->len < 4) {
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
                // Packet is too short for IPv4 header
                return;
            }

            struct ip *ip_hdr = (struct ip*)ip_packet;
            inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

            // Determine packet direction
            int direction;
            if (is_local_ip(src_ip)) {
                direction = 1; 
            }
            else if (is_local_ip(dst_ip)) {
                direction = 0;
            }
            else {
                if (debug_mode) {
                fprintf(log_file, "No local IP found. Default direction set: %s -> %s\n", src_ip, dst_ip);
                 }
               direction = 1;
            }

            uint8_t protocol_num = ip_hdr->ip_p;

            const u_char *transport_header = ip_packet + (ip_hdr->ip_hl * 4);

            if (protocol_num == IPPROTO_TCP) {
                if (header->len < 4 + (ip_hdr->ip_hl * 4) + sizeof(struct tcphdr)) {
                    return;
                }
                struct tcphdr *tcp_hdr = (struct tcphdr*)transport_header;
                src_port = ntohs(TCP_SRC_PORT(tcp_hdr));
                dst_port = ntohs(TCP_DST_PORT(tcp_hdr));
                strcpy(protocol, "tcp");
            }
            else if (protocol_num == IPPROTO_UDP) {
                if (header->len < 4 + (ip_hdr->ip_hl * 4) + sizeof(struct udphdr)) {
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
                // Packet is too short for IPv6 header
                return;
            }

            struct ip6_hdr *ip6_hdr = (struct ip6_hdr*)ip_packet;
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

            // Determine packet direction
            int direction;
            if (is_local_ip(src_ip)) {
                direction = 1; 
            }
            else if (is_local_ip(dst_ip)) {
                direction = 0; 
            }
            else {
                if (debug_mode) {
                fprintf(log_file, "No local IP found. Default direction set: %s -> %s\n", src_ip, dst_ip);
                 }
                direction = 1;
            }

            uint8_t next_header = ip6_hdr->ip6_nxt;
            uint16_t src_port = 0;
            uint16_t dst_port = 0;
            char proto_str[8] = "other";

            const u_char *transport_header = ip_packet + sizeof(struct ip6_hdr);

            if (next_header == IPPROTO_TCP) {
                if (header->len < 4 + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)) {
                    return;
                }
                struct tcphdr *tcp_hdr = (struct tcphdr*)transport_header;
                src_port = ntohs(TCP_SRC_PORT(tcp_hdr));
                dst_port = ntohs(TCP_DST_PORT(tcp_hdr));
                strcpy(proto_str, "tcp");
            }
            else if (next_header == IPPROTO_UDP) {
                if (header->len < 4 + sizeof(struct ip6_hdr) + sizeof(struct udphdr)) {
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

// Function to update connection statistics
void update_connection(char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port,
                       char *protocol, uint32_t bytes, int direction) {
    ConnectionKey key;

    if (debug_mode) {
        fprintf(log_file, "Received packet: %s:%d -> %s:%d (%s), %d bytes, direction: %d\n",
                src_ip, src_port, dst_ip, dst_port, protocol, bytes, direction);
    }



    // IP addresses and ports are sorted in ascending order
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
            connections[index].last_direction = direction;
            if (debug_mode)
                fprintf(log_file, "Added new connection: %s:%d <-> %s:%d (%s)\n",
                        key.ip1, key.port1, key.ip2, key.port2, key.protocol);
        } else {
            if (debug_mode)
                fprintf(log_file, "Exceeded maximum number of connections (%d)\n", MAX_CONNECTIONS);
            return;
        }
    }

    connections[index].last_direction = direction;

    if (direction == 0) { // Receive (Rx)
        connections[index].rx_bytes += bytes;
        connections[index].rx_packets += 1;
    } else { // Transmit (Tx)
        connections[index].tx_bytes += bytes;
        connections[index].tx_packets += 1;
    }
}

// Function to find connection index by key
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

// Function to compare connection keys
int compare_keys(ConnectionKey *key1, ConnectionKey *key2) {
    // Compare both directions
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

