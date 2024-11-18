// isa-top.h

/**
 * Author: Maksim Samusevich
 * Login: xsamus00
 **/

#ifndef ISA_TOP_H
#define ISA_TOP_H

#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ncurses.h>

#define MAX_CONNECTIONS 1000
#define MAX_IP_ADDRESSES 10

// Macros for getting source and destination ports
#if defined(__APPLE__) || defined(__MACH__)
// macOS
#define TCP_SRC_PORT(th) ((th)->th_sport)
#define TCP_DST_PORT(th) ((th)->th_dport)
#define UDP_SRC_PORT(uh) ((uh)->uh_sport)
#define UDP_DST_PORT(uh) ((uh)->uh_dport)
#else
// Linux and other systems
#define TCP_SRC_PORT(th) ((th)->source)
#define TCP_DST_PORT(th) ((th)->dest)
#define UDP_SRC_PORT(uh) ((uh)->source)
#define UDP_DST_PORT(uh) ((uh)->dest)
#endif

// Structure for connection statistics
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
    int last_direction;
    
} Connection;

// Structure for connection key
typedef struct {
    char ip1[INET6_ADDRSTRLEN];
    char ip2[INET6_ADDRSTRLEN];
    uint16_t port1;
    uint16_t port2;
    char protocol[8];
} ConnectionKey;


extern Connection connections[MAX_CONNECTIONS];
extern int connection_count;

// External variables
extern char *interface;
extern char sort_mode;
extern int interval;
extern int debug_mode;

// External variables for pcap
extern int linktype;
extern pcap_t *handle;

// External log file variable
extern FILE *log_file;

// Function prototypes
void sleep_ms(long milliseconds);
int parse_arguments(int argc, char *argv[]);
void print_usage();
void handle_sigint();
void get_local_ips(char *interface);
int is_local_ip(char *ip);
int is_ipv6_address(const char *ip);
int compare_keys(ConnectionKey *key1, ConnectionKey *key2);
int find_connection(ConnectionKey *key);
void update_connection(char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port,
                       char *protocol, uint32_t bytes, int direction);
void format_value(double value, char *output, char *unit_str);
void format_bandwidth(double bytes, double interval, char *output, char *unit_str);
int compare_bytes(const void *a, const void *b);
int compare_packets(const void *a, const void *b);
void display_statistics();
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif // ISA_TOP_H
