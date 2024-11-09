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
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    char protocol[8];
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t tx_packets;
    time_t last_update;
} Connection;

Connection connections[MAX_CONNECTIONS];
int connection_count = 0;

// Глобальные переменные для настроек
char *interface = NULL;
char sort_mode = 'b';
int interval = 1;

volatile sig_atomic_t stop = 0;

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
    fprintf(stderr, "Использование: isa-top -i <interface> [-s b|p] [-t interval]\n");
    fprintf(stderr, "  -i <interface> : Укажите сетевой интерфейс для мониторинга (обязательно)\n");
    fprintf(stderr, "  -s b|p         : Режим сортировки: 'b' для байтов, 'p' для пакетов (по умолчанию 'b')\n");
    fprintf(stderr, "  -t interval    : Интервал обновления статистики в секундах (по умолчанию 1)\n");
}

// Обработчик сигнала SIGINT
void handle_sigint(int sig) {
    fprintf(stderr, "Получен сигнал SIGINT, завершаем работу...\n");
    stop = 1;
}

// Проверка, является ли IP-адрес локальным
int is_local_ip(char *ip) {
    for (int i = 0; i < local_ip_count; i++) {
        if (strcmp(ip, local_ips[i]) == 0) {
            return 1;
        }
    }
    return 0;
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
                fprintf(stderr, "Локальный IP адрес (%s): %s\n", interface, host);
                local_ip_count++;
            } else {
                fprintf(stderr, "getnameinfo() failed: %s\n", gai_strerror(s));
            }
        }
    }

    freeifaddrs(ifaddr);
}

// Поиск существующего соединения
int find_connection(char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port, char *protocol) {
    for (int i = 0; i < connection_count; i++) // Поиск существующего соединения
    {
        if (strcmp(connections[i].src_ip, src_ip) == 0 &&
            strcmp(connections[i].dst_ip, dst_ip) == 0 &&
            connections[i].src_port == src_port &&
            connections[i].dst_port == dst_port &&
            strcmp(connections[i].protocol, protocol) == 0) {
            fprintf(stderr, "Найдено существующее соединение (%s:%d -> %s:%d)\n", src_ip, src_port, dst_ip, dst_port);
            return i;
        }
    }
    // Новое соединение
    fprintf(stderr, "Новое соединение (%s:%d -> %s:%d)\n", src_ip, src_port, dst_ip, dst_port);
    return -1;
}

// Обновление статистики соединения
void update_connection(char *src_ip, char *dst_ip, uint16_t src_port, uint16_t dst_port, char *protocol, uint32_t bytes, int direction) {
    int index = find_connection(src_ip, dst_ip, src_port, dst_port, protocol);
    if (index == -1) {
        if (connection_count < MAX_CONNECTIONS) {
            index = connection_count++;
            strcpy(connections[index].src_ip, src_ip);
            strcpy(connections[index].dst_ip, dst_ip);
            connections[index].src_port = src_port;
            connections[index].dst_port = dst_port;
            strcpy(connections[index].protocol, protocol);
            connections[index].rx_bytes = 0;
            connections[index].tx_bytes = 0;
            connections[index].rx_packets = 0;
            connections[index].tx_packets = 0;
            connections[index].last_update = time(NULL);
            fprintf(stderr, "Добавлено новое соединение в список (index: %d)\n", index);
        } else {
            fprintf(stderr, "Превышено максимальное количество соединений (%d)\n", MAX_CONNECTIONS);
            return;
        }
    }

    if (direction == 0) { // Прием
        connections[index].rx_bytes += bytes;
        connections[index].rx_packets += 1;
        fprintf(stderr, "Обновление IN для соединения %d: +%u байт, DIERCTION == %d\n", index, bytes, direction);
    } else { // Передача
        connections[index].tx_bytes += bytes;
        connections[index].tx_packets += 1;
        fprintf(stderr, "Обновление OUT для соединения %d: +%u байт, DIERCTION == %d\n", index, bytes, direction);
    }
    connections[index].last_update = time(NULL);
}

// Форматирование скорости передачи данных
void format_bandwidth(double bytes, double interval, char *output) {
    double bps = bytes / interval;
    const char *units[] = {"B/s", "KB/s", "MB/s", "GB/s"};
    int unit = 0;
    while (bps >= 1024 && unit < 3) {
        bps /= 1024;
        unit++;
    }
    snprintf(output, 16, "%.1f %s", bps, units[unit]);
}

// Сравнение по общему количеству байт
int compare_bytes(const void *a, const void *b) {
    Connection *connA = (Connection *)a;
    Connection *connB = (Connection *)b;
    uint64_t totalA = connA->rx_bytes + connA->tx_bytes;
    uint64_t totalB = connB->rx_bytes + connB->tx_bytes;
    return (totalB > totalA) - (totalB < totalA);
}

// Сравнение по общему количеству пакетов
int compare_packets(const void *a, const void *b) {
    Connection *connA = (Connection *)a;
    Connection *connB = (Connection *)b;
    uint64_t totalA = connA->rx_packets + connA->tx_packets;
    uint64_t totalB = connB->rx_packets + connB->tx_packets;
    return (totalB > totalA) - (totalB < totalA);
}

// Отображение статистики
void display_statistics() {
    fprintf(stderr, "Обновление статистики...\n");

    // Сортируем соединения
    if (sort_mode == 'b') {
        qsort(connections, connection_count, sizeof(Connection), compare_bytes);
        fprintf(stderr, "Соединения отсортированы по байтам\n");
    } else {
        qsort(connections, connection_count, sizeof(Connection), compare_packets);
        fprintf(stderr, "Соединения отсортированы по пакетам\n");
    }

    // Очищаем экран
    clear();

    // Выводим заголовки
    mvprintw(0, 0, "Src IP:port                    Dst IP:port                    Proto    Rx                Tx");

    // Текущее время для вычисления скорости
    time_t now = time(NULL);

    // Выводим топ-10 соединений
    for (int i = 0; i < connection_count && i < 10; i++) {
        char src[50], dst[50], rx_bw[16], tx_bw[16];
        snprintf(src, 50, "%s:%d", connections[i].src_ip, connections[i].src_port);
        snprintf(dst, 50, "%s:%d", connections[i].dst_ip, connections[i].dst_port);

        double time_diff = difftime(now, connections[i].last_update);
        if (time_diff == 0) time_diff = interval;

        format_bandwidth(connections[i].rx_bytes, time_diff, rx_bw);
        format_bandwidth(connections[i].tx_bytes, time_diff, tx_bw);

        mvprintw(i + 2, 0, "%-30s %-30s %-8s %-15s %-15s",
                 src, dst, connections[i].protocol, rx_bw, tx_bw);

        fprintf(stderr, "Соединение %d: %s:%d -> %s:%d, Протокол: %s, Rx: %s, Tx: %s\n",
                i, connections[i].src_ip, connections[i].src_port,
                connections[i].dst_ip, connections[i].dst_port,
                connections[i].protocol, rx_bw, tx_bw);

        // Сбрасываем счетчики после отображения
        connections[i].rx_bytes = 0;
        connections[i].tx_bytes = 0;
        connections[i].rx_packets = 0;
        connections[i].tx_packets = 0;
        connections[i].last_update = now;
    }

    // Обновляем экран
    refresh();
}

// Обработчик захваченного пакета
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    fprintf(stderr, "Захвачен пакет длиной %u байт\n", header->len);
    int ethernet_header_length = 14; // Стандартная длина Ethernet заголовка

    uint16_t eth_type = ntohs(*(uint16_t*)(packet + 12));
    fprintf(stderr, "Ethernet Type: 0x%04x\n", eth_type);
    int direction;

    if (eth_type == 0x0800) { // IPv4
        struct ip *ip_hdr = (struct ip*)(packet + ethernet_header_length);
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);
        fprintf(stderr, "IPv4 пакет: %s -> %s\n", src_ip, dst_ip);

        // Определяем направление пакета
        if (is_local_ip(src_ip)) {
            // Исходящий пакет
            direction = 1;
        } else if (is_local_ip(dst_ip)) {
            // Входящий пакет
            direction = 0;
        } else {
            // Пакет не относится к нашему хосту
            return;
        }
        fprintf(stderr, "Направление пакета: %s\n", direction == 0 ? "Входящий" : "Исходящий");

        uint8_t protocol = ip_hdr->ip_p;
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        char proto_str[8];

        const u_char *transport_header = packet + ethernet_header_length + (ip_hdr->ip_hl * 4);

        if (protocol == IPPROTO_TCP) {
            struct tcphdr *tcp_hdr = (struct tcphdr*)transport_header;
            src_port = ntohs(TCP_SRC_PORT(tcp_hdr));
            dst_port = ntohs(TCP_DST_PORT(tcp_hdr));
            strcpy(proto_str, "tcp");
            fprintf(stderr, "TCP пакет: %s:%d -> %s:%d\n", src_ip, src_port, dst_ip, dst_port);
        } else if (protocol == IPPROTO_UDP) {
            struct udphdr *udp_hdr = (struct udphdr*)transport_header;
            src_port = ntohs(UDP_SRC_PORT(udp_hdr));
            dst_port = ntohs(UDP_DST_PORT(udp_hdr));
            strcpy(proto_str, "udp");
            fprintf(stderr, "UDP пакет: %s:%d -> %s:%d\n", src_ip, src_port, dst_ip, dst_port);
        } else if (protocol == IPPROTO_ICMP) {
            strcpy(proto_str, "icmp");
            fprintf(stderr, "ICMP пакет: %s -> %s\n", src_ip, dst_ip);
        } else {
            strcpy(proto_str, "other");
            fprintf(stderr, "Другой протокол (%d): %s -> %s\n", protocol, src_ip, dst_ip);
        }

        update_connection(src_ip, dst_ip, src_port, dst_port, proto_str, header->len, direction);

    } else if (eth_type == 0x86DD) { // IPv6
        struct ip6_hdr *ip6_hdr = (struct ip6_hdr*)(packet + ethernet_header_length);
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
        fprintf(stderr, "IPv6 пакет: %s -> %s\n", src_ip, dst_ip);

        // Определяем направление пакета
        if (is_local_ip(src_ip)) {
            // Исходящий пакет
            direction = 1;
        } else if (is_local_ip(dst_ip)) {
            // Входящий пакет
            direction = 0;
        } else {
            // Пакет не относится к нашему хосту
            return;
        }

        uint8_t next_header = ip6_hdr->ip6_nxt;
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        char proto_str[8];

        const u_char *transport_header = packet + ethernet_header_length + sizeof(struct ip6_hdr);

        if (next_header == IPPROTO_TCP) {
            struct tcphdr *tcp_hdr = (struct tcphdr*)transport_header;
            src_port = ntohs(TCP_SRC_PORT(tcp_hdr));
            dst_port = ntohs(TCP_DST_PORT(tcp_hdr));
            strcpy(proto_str, "tcp");
            fprintf(stderr, "TCP6 пакет: %s:%d -> %s:%d\n", src_ip, src_port, dst_ip, dst_port);
        } else if (next_header == IPPROTO_UDP) {
            struct udphdr *udp_hdr = (struct udphdr*)transport_header;
            src_port = ntohs(UDP_SRC_PORT(udp_hdr));
            dst_port = ntohs(UDP_DST_PORT(udp_hdr));
            strcpy(proto_str, "udp");
            fprintf(stderr, "UDP6 пакет: %s:%d -> %s:%d\n", src_ip, src_port, dst_ip, dst_port);
        } else if (next_header == IPPROTO_ICMPV6) {
            strcpy(proto_str, "icmp6");
            fprintf(stderr, "ICMPv6 пакет: %s -> %s\n", src_ip, dst_ip);
        } else {
            strcpy(proto_str, "other");
            fprintf(stderr, "Другой протокол IPv6 (%d): %s -> %s\n", next_header, src_ip, dst_ip);
        }

        update_connection(src_ip, dst_ip, src_port, dst_port, proto_str, header->len, direction);

    } else {
        // Не IPv4 и не IPv6
        fprintf(stderr, "Неизвестный Ethernet Type: 0x%04x\n", eth_type);
        return;
    }
}

// Функция парсинга аргументов командной строки
int parse_arguments(int argc, char *argv[], Settings *settings) {
    int opt;
    // Инициализация значений по умолчанию
    settings->interface = NULL;
    settings->sort_mode = 'b';
    settings->interval = 1;

    while ((opt = getopt(argc, argv, "i:s:t:")) != -1) {
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
    fprintf(stderr, "Запуск программы isa-top\n");

    Settings settings;
    if (parse_arguments(argc, argv, &settings) != 0) {
        exit(EXIT_FAILURE);
    }

    // Установка глобальных переменных на основе настроек
    interface = settings.interface;
    sort_mode = settings.sort_mode;
    interval = settings.interval;

    fprintf(stderr, "Выбран интерфейс: %s\n", interface);
    fprintf(stderr, "Режим сортировки: %c\n", sort_mode);
    fprintf(stderr, "Интервал обновления: %d секунд\n", interval);

    signal(SIGINT, handle_sigint);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Не удалось открыть устройство %s: %s\n", interface, errbuf);
        return EXIT_FAILURE;
    }
    fprintf(stderr, "Устройство %s успешно открыто для захвата\n", interface);

    // Получаем локальные IP-адреса
    get_local_ips(interface);

    // Инициализация ncurses
    initscr();
    cbreak();
    noecho();
    curs_set(FALSE);

    fprintf(stderr, "Начало цикла захвата пакетов\n");
    while (!stop) {
        int ret = pcap_dispatch(handle, -1, packet_handler, NULL);
        if (ret == -1) {
            fprintf(stderr, "Ошибка при захвате пакетов: %s\n", pcap_geterr(handle));
            break;
        } else if (ret == 0) {
            fprintf(stderr, "Нет пакетов для обработки\n");
        } else {
            fprintf(stderr, "Обработано %d пакетов\n", ret);
        }
        display_statistics();
        sleep(interval);
    }

    fprintf(stderr, "Завершение работы программы\n");
    pcap_close(handle);
    endwin();
    return EXIT_SUCCESS;
}
