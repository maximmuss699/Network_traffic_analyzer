#ifndef UTILS_H
#define UTILS_H

#include "isa-top.h"

// Maximum number of local IP addresses
#define MAX_IP_ADDRESSES 100

extern char local_ips[MAX_IP_ADDRESSES][INET6_ADDRSTRLEN];
extern int local_ip_count;

// Function prototypes
void sleep_ms(long milliseconds);
void get_local_ips(char *interface);
int is_local_ip(char *ip);
int is_ipv6_address(const char *ip);
void format_value(double value, char *output, char *unit_str);
void format_bandwidth(double bytes, double interval, char *output, char *unit_str);
void print_usage();
int parse_arguments(int argc, char *argv[]);

#endif // UTILS_H
