// isa-top.c

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>       // Для getopt()
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
// Linux и другие
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

Connection connections[MAX_CONNECTIONS];
int connection_count = 0;

// Глобальные переменные для настроек
char *interface = NULL;
char sort_mode = 'b';
int interval = 1;
int debug_mode = 0;

int linktype = -1;

volatile sig_atomic_t stop = 0;

pcap_t *handle = NULL;

// Переменная для файла логирования
FILE *log_file = NULL;

// Структура для хранения настроек
typedef struct {
    char *interface;
    char sort_mode;
    int interval;
} Settings;

// Прототип функции парсинга аргументов
int parse_arguments(int argc, char *argv[], Settings *settings);

// Функция вывода справки
void print_usage() {
    fprintf(stderr, "Использование: isa-top -i <interface> [-s b|p] [-t interval] [-d]\n");
    fprintf(stderr, "  -i <interface> : Укажите сетевой интерфейс для мониторинга (обязательно)\n");
    fprintf(stderr, "  -s b|p         : Режим сортировки: 'b' для байтов, 'p' для пакетов (по умолчанию 'b')\n");
    fprintf(stderr, "  -t interval    : Интервал обновления статистики в секундах (по умолчанию 1)\n");
    fprintf(stderr, "  -d             : Включить режим отладки\n");
}

// Обработчик сигнала SIGINT
void handle_sigint(int sig) {
    pcap_breakloop(handle);
    stop = 1;
}

// Получение локальных IP-адресов указанного интерфейса
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

        // Проверяем только указанный интерфейс
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
                    fprintf(log_file, "Локальный IP адрес (%s): %s\n", interface, host);
                local_ip_count++;
            } else {
                fprintf(stderr, "getnameinfo() failed: %s\n", gai_strerror(s));
            }
        }
    }

    freeifaddrs(ifaddr);
}

// Проверка, является ли IP локальным
int is_local_ip(char *ip) {
    char ip_copy[INET6_ADDRSTRLEN];
    char packet_ip_copy[INET6_ADDRSTRLEN];

    for (int i = 0; i < local_ip_count; i++) {
        // Копируем локальный IP и удаляем идентификатор области, если есть
        strncpy(ip_copy, local_ips[i], INET6_ADDRSTRLEN);
        char *percent = strchr(ip_copy, '%');
        if (percent) {
            *percent = '\0';
        }

        // Копируем IP из пакета и удаляем идентификатор области, если есть
        strncpy(packet_ip_copy, ip, INET6_ADDRSTRLEN);
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

// Структура для создания уникального ключа соединения
typedef struct {
    char ip1[INET6_ADDRSTRLEN];
    char ip2[INET6_ADDRSTRLEN];
    uint16_t port1;
    uint16_t port2;
    char protocol[8];
} ConnectionKey;

// Сравнение двух ключей соединений (без учета направления)
int compare_keys(ConnectionKey *key1, ConnectionKey *key2) {
    // Сравниваем ip1 и ip2 в обоих направлениях
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

// Поиск существующего соединения независимо от направления
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
    // Новое соединение
    return -1;
}

// Обновление статистики соединения
void update_connection(char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port,
                      char *protocol, uint32_t bytes, int direction) {
    ConnectionKey key;

    // Упорядочиваем IP и порты для консистентности
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
                fprintf(log_file, "Добавлено новое соединение: %s:%d <-> %s:%d (%s)\n",
                        key.ip1, key.port1, key.ip2, key.port2, key.protocol);
        } else {
            if (debug_mode)
                fprintf(log_file, "Превышено максимальное количество соединений (%d)\n", MAX_CONNECTIONS);
            return;
        }
    }

    if (direction == 0) { // Прием (Rx)
        connections[index].rx_bytes += bytes;
        connections[index].rx_packets += 1;
    } else { // Передача (Tx)
        connections[index].tx_bytes += bytes;
        connections[index].tx_packets += 1;
    }
}

void format_bandwidth(double bytes, double interval, char *output, char *unit_str) {
    double bps = bytes / interval;
    const char *units[] = {"B", "k", "M", "G"};
    int unit = 0;
    while (bps >= 1024 && unit < 3) {
        bps /= 1024;
        unit++;
    }
    strcpy(unit_str, units[unit]);
    snprintf(output, 16, "%.1f", bps);
}

// Сравнение по общему количеству байт
int compare_bytes(const void *a, const void *b) {
    Connection *connA = (Connection *)a;
    Connection *connB = (Connection *)b;
    uint64_t totalA = connA->rx_bytes + connA->tx_bytes;
    uint64_t totalB = connB->rx_bytes + connB->tx_bytes;
    if (totalA < totalB) return 1;
    if (totalA > totalB) return -1;
    return 0;
}

// Сравнение по общему количеству пакетов
int compare_packets(const void *a, const void *b) {
    Connection *connA = (Connection *)a;
    Connection *connB = (Connection *)b;
    uint64_t totalA = connA->rx_packets + connA->tx_packets;
    uint64_t totalB = connB->rx_packets + connB->tx_packets;
    if (totalA < totalB) return 1;
    if (totalA > totalB) return -1;
    return 0;
}

// Отображение статистики
void display_statistics() {
    // Очищаем экран
    clear();

    // Выводим заголовки
    mvprintw(0, 0, "Src IP:port                          Dst IP:port                     Proto             Rx         Tx");
    mvprintw(1, 0, "                                                                                          b/s p/s     b/s p/s");

    // Сортируем соединения
    if (sort_mode == 'b') {
        qsort(connections, connection_count, sizeof(Connection), compare_bytes);
        if (debug_mode)
            fprintf(log_file, "Соединения отсортированы по байтам\n");
    } else {
        qsort(connections, connection_count, sizeof(Connection), compare_packets);
        if (debug_mode)
            fprintf(log_file, "Соединения отсортированы по пакетам\n");
    }

    // Выводим топ-10 соединений
    for (int i = 0; i < connection_count && i < 10; i++) {
        char src[50], dst[50], rx_bw[16], tx_bw[16];
        snprintf(src, 50, "%s:%d", connections[i].ip1, connections[i].port1);
        snprintf(dst, 50, "%s:%d", connections[i].ip2, connections[i].port2);

        double time_diff = (double)interval;
        if (time_diff == 0) time_diff = 1.0;

        char rx_unit[4], tx_unit[4];
        format_bandwidth(connections[i].rx_bytes, time_diff, rx_bw, rx_unit);
        format_bandwidth(connections[i].tx_bytes, time_diff, tx_bw, tx_unit);

        // Вычисляем пакеты в секунду
        double rx_pps = connections[i].rx_packets / time_diff;
        double tx_pps = connections[i].tx_packets / time_diff;

        // Форматируем строку вывода
        mvprintw(i + 2, 0, "%-30s %-30s %-8s %-6s%-2s %-4.1f %-6s%-2s %-4.1f",
                 src, dst, connections[i].protocol,
                 rx_bw, rx_unit, rx_pps,
                 tx_bw, tx_unit, tx_pps);

        if (debug_mode) {
            fprintf(log_file, "Соединение %d: %s <-> %s, Протокол: %s, Rx: %s%s (%.1f p/s), Tx: %s%s (%.1f p/s)\n",
                    i, src, dst, connections[i].protocol, rx_bw, rx_unit, rx_pps, tx_bw, tx_unit, tx_pps);
        }

        // Сбрасываем счетчики после отображения
        connections[i].rx_bytes = 0;
        connections[i].tx_bytes = 0;
        connections[i].rx_packets = 0;
        connections[i].tx_packets = 0;
    }

    // Обновляем экран
    refresh();
}

// Обработчик захваченного пакета
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    if (debug_mode)
        fprintf(log_file, "Захвачен пакет длиной %u байт\n", header->len);

    if (linktype == DLT_EN10MB) { // Ethernet
        int ethernet_header_length = 14; // Стандартная длина Ethernet заголовка
        if (header->len < ethernet_header_length) {
            // Пакет слишком короткий для Ethernet заголовка
            return;
        }

        uint16_t eth_type = ntohs(*(uint16_t*)(packet + 12));

        if (eth_type == 0x0800) { // IPv4
            if (header->len < ethernet_header_length + sizeof(struct ip)) {
                // Пакет слишком короткий для IPv4 заголовка
                return;
            }

            struct ip *ip_hdr = (struct ip*)(packet + ethernet_header_length);
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

            // Определяем направление пакета
            int direction;
            if (is_local_ip(src_ip)) {
                direction = 1; // Исходящий
            } else if (is_local_ip(dst_ip)) {
                direction = 0; // Входящий
            } else {
                // Пакет не относится к нашему хосту
                return;
            }

            uint8_t protocol = ip_hdr->ip_p;
            uint16_t src_port = 0;
            uint16_t dst_port = 0;
            char proto_str[8] = "other";

            const u_char *transport_header = packet + ethernet_header_length + (ip_hdr->ip_hl * 4);

            if (protocol == IPPROTO_TCP) {
                if (header->len < ethernet_header_length + (ip_hdr->ip_hl * 4) + sizeof(struct tcphdr)) {
                    // Пакет слишком короткий для TCP заголовка
                    return;
                }
                struct tcphdr *tcp_hdr = (struct tcphdr*)transport_header;
                src_port = ntohs(TCP_SRC_PORT(tcp_hdr));
                dst_port = ntohs(TCP_DST_PORT(tcp_hdr));
                strcpy(proto_str, "tcp");
            }
            else if (protocol == IPPROTO_UDP) {
                if (header->len < ethernet_header_length + (ip_hdr->ip_hl * 4) + sizeof(struct udphdr)) {
                    // Пакет слишком короткий для UDP заголовка
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
                // Пакет слишком короткий для IPv6 заголовка
                return;
            }

            struct ip6_hdr *ip6_hdr = (struct ip6_hdr*)(packet + ethernet_header_length);
            char src_ip[INET6_ADDRSTRLEN];
            char dst_ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

            // Определяем направление пакета
            int direction;
            if (is_local_ip(src_ip)) {
                direction = 1; // Исходящий
            }
            else if (is_local_ip(dst_ip)) {
                direction = 0; // Входящий
            }
            else {
                // Пакет не относится к нашему хосту
                return;
            }

            uint8_t next_header = ip6_hdr->ip6_nxt;
            uint16_t src_port = 0;
            uint16_t dst_port = 0;
            char proto_str[8] = "other";

            const u_char *transport_header = packet + ethernet_header_length + sizeof(struct ip6_hdr);

            if (next_header == IPPROTO_TCP) {
                if (header->len < ethernet_header_length + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)) {
                    // Пакет слишком короткий для TCP заголовка
                    return;
                }
                struct tcphdr *tcp_hdr = (struct tcphdr*)transport_header;
                src_port = ntohs(TCP_SRC_PORT(tcp_hdr));
                dst_port = ntohs(TCP_DST_PORT(tcp_hdr));
                strcpy(proto_str, "tcp");
            }
            else if (next_header == IPPROTO_UDP) {
                if (header->len < ethernet_header_length + sizeof(struct ip6_hdr) + sizeof(struct udphdr)) {
                    // Пакет слишком короткий для UDP заголовка
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
    else if (linktype == DLT_NULL) { // Loopback (например, lo0 на macOS)
        if (header->len < 4) {
            // Пакет слишком короткий для заголовка DLT_NULL
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
                // Пакет слишком короткий для IPv4 заголовка
                return;
            }

            struct ip *ip_hdr = (struct ip*)ip_packet;
            inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

            // Определяем направление пакета
            int direction;
            if (is_local_ip(src_ip)) {
                direction = 1; // Исходящий
            }
            else if (is_local_ip(dst_ip)) {
                direction = 0; // Входящий
            }
            else {
                // Пакет не относится к нашему хосту
                return;
            }

            uint8_t protocol_num = ip_hdr->ip_p;

            const u_char *transport_header = ip_packet + (ip_hdr->ip_hl * 4);

            if (protocol_num == IPPROTO_TCP) {
                if (header->len < 4 + (ip_hdr->ip_hl * 4) + sizeof(struct tcphdr)) {
                    // Пакет слишком короткий для TCP заголовка
                    return;
                }
                struct tcphdr *tcp_hdr = (struct tcphdr*)transport_header;
                src_port = ntohs(TCP_SRC_PORT(tcp_hdr));
                dst_port = ntohs(TCP_DST_PORT(tcp_hdr));
                strcpy(protocol, "tcp");
            }
            else if (protocol_num == IPPROTO_UDP) {
                if (header->len < 4 + (ip_hdr->ip_hl * 4) + sizeof(struct udphdr)) {
                    // Пакет слишком короткий для UDP заголовка
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
                // Пакет слишком короткий для IPv6 заголовка
                return;
            }

            struct ip6_hdr *ip6_hdr = (struct ip6_hdr*)ip_packet;
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

            // Определяем направление пакета
            int direction;
            if (is_local_ip(src_ip)) {
                direction = 1; // Исходящий
            }
            else if (is_local_ip(dst_ip)) {
                direction = 0; // Входящий
            }
            else {
                // Пакет не относится к нашему хосту
                return;
            }

            uint8_t next_header = ip6_hdr->ip6_nxt;
            uint16_t src_port = 0;
            uint16_t dst_port = 0;
            char proto_str[8] = "other";

            const u_char *transport_header = ip_packet + sizeof(struct ip6_hdr);

            if (next_header == IPPROTO_TCP) {
                if (header->len < 4 + sizeof(struct ip6_hdr) + sizeof(struct tcphdr)) {
                    // Пакет слишком короткий для TCP заголовка
                    return;
                }
                struct tcphdr *tcp_hdr = (struct tcphdr*)transport_header;
                src_port = ntohs(TCP_SRC_PORT(tcp_hdr));
                dst_port = ntohs(TCP_DST_PORT(tcp_hdr));
                strcpy(proto_str, "tcp");
            }
            else if (next_header == IPPROTO_UDP) {
                if (header->len < 4 + sizeof(struct ip6_hdr) + sizeof(struct udphdr)) {
                    // Пакет слишком короткий для UDP заголовка
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
            // Неизвестный семейство адресов
            return;
        }
    }
}

// Функция парсинга аргументов командной строки
int parse_arguments(int argc, char *argv[], Settings *settings) {
    int opt;
    // Инициализация значений по умолчанию
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
                    fprintf(stderr, "Неверный режим сортировки: %c\n", optarg[0]);
                    return -1;
                }
                break;
            case 't':
                settings->interval = atoi(optarg);
                if (settings->interval <= 0) {
                    fprintf(stderr, "Интервал должен быть положительным числом\n");
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

    // Проверка обязательного параметра
    if (settings->interface == NULL) {
        fprintf(stderr, "Ошибка: Не указан сетевой интерфейс\n");
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

    // Установка глобальных переменных на основе настроек
    interface = settings.interface;
    sort_mode = settings.sort_mode;
    interval = settings.interval;

    // Открытие файла для логирования
    log_file = fopen("isa-top.log", "w");
    if (log_file == NULL) {
        perror("Не удалось открыть файл isa-top.log для логирования");
        exit(EXIT_FAILURE);
    }

    // Установка обработчика сигнала SIGINT
    signal(SIGINT, handle_sigint);

    // Получение локальных IP-адресов
    get_local_ips(interface);

    // Инициализация pcap
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        endwin();
        fprintf(stderr, "Не удалось открыть устройство %s: %s\n", interface, errbuf);
        fclose(log_file);
        return EXIT_FAILURE;
    }

    // Установка неблокирующего режима для pcap
    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        endwin();
        fprintf(stderr, "Ошибка установки неблокирующего режима: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        fclose(log_file);
        return EXIT_FAILURE;
    }

    // Определение типа связующего уровня
    linktype = pcap_datalink(handle);

    // Инициализация ncurses
    initscr();
    cbreak();
    noecho();
    curs_set(FALSE);

    // Инициализация переменных для отслеживания времени
    struct timeval last_time, current_time;
    gettimeofday(&last_time, NULL);

    while (!stop) {
        // Проверяем, прошел ли интервал
        gettimeofday(&current_time, NULL);
        double elapsed = (current_time.tv_sec - last_time.tv_sec) + (current_time.tv_usec - last_time.tv_usec) / 1e6;
        if (elapsed >= interval) {
            display_statistics();
            last_time = current_time;
        }

        // Захватываем следующий пакет (неблокирующий)
        struct pcap_pkthdr *header;
        const u_char *packet;
        int ret = pcap_next_ex(handle, &header, &packet);
        if (ret == 1) {
            packet_handler(NULL, header, packet);
        } else if (ret == 0) {
            // Нет пакетов в буфере, спим немного
            if (debug_mode)
                fprintf(log_file, "Нет пакетов в буфере\n");
            usleep(1000); // Спим 1 мс
        } else if (ret == -1) {
            fprintf(stderr, "Ошибка при захвате пакетов: %s\n", pcap_geterr(handle));
            break;
        } else if (ret == -2) {
            // pcap_breakloop() был вызван
            break;
        }
    }

    // Завершение работы
    pcap_close(handle);
    endwin();
    fclose(log_file);
    return EXIT_SUCCESS;
}
