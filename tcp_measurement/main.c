/*
 * Copyright (C) 2017 smlng
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "shell.h"

#include "measurement.h"

#ifndef USE_LWIP_TCP
extern int _gnrc_tcp_recv(uint16_t port, uint32_t bytes, uint16_t loops);
extern int _gnrc_tcp_send(const ipv6_addr_t *addr, uint16_t port, uint32_t bytes, uint16_t loops);
#else
#include "lwip.h"
#include "lwip/netif.h"
extern int _lwip_tcp_recv(uint16_t port, uint32_t bytes, uint16_t loops);
extern int _lwip_tcp_send(const ipv6_addr_t *addr, uint16_t port, uint32_t bytes, uint16_t loops);
#endif /* USE_LWIP_TCP */

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

static int tcp_recv(int argc, char **argv);
static int tcp_send(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    { "listen", "receive TCP", tcp_recv },
    { "send", "send TCP", tcp_send },
    { NULL, NULL, NULL }
};

uint8_t buf[TCP_BUFLEN];

static int tcp_recv(int argc, char **argv)
{
    if ((argc != 3) && (argc != 4)) {
        LOG_ERROR("usage: listen <port> <bytes> [loops]\n");
        return -1;
    }
    /* parse port */
    uint16_t port = (uint16_t)atoi(argv[1]);
    if (port <= 0) {
        LOG_ERROR("send: unable to parse destination port!\n");
        return -3;
    }
    /* parse num bytes */
    uint32_t bytes = (uint32_t)atoi(argv[2]);
    if (bytes <= 0) {
        LOG_ERROR("send: unable to parse number of bytes to send!");
        return -4;
    }
    uint16_t loops = 1;
    if (argc == 4) {
        loops = (uint16_t)atoi(argv[3]);
        if (loops <= 0) {
            LOG_ERROR("send: unable to parse number of loops!\n");
            return -5;
        }
    }
    #ifdef USE_LWIP_TCP
        return _lwip_tcp_recv(port, bytes, loops);
    #else
        return _gnrc_tcp_recv(port, bytes, loops);
    #endif /* USE_LWIP_TCP */
}

static int tcp_send(int argc, char **argv)
{
    if ((argc != 4) && (argc != 5)) {
        puts("usage: send <addr> <port> <size> [loops]");
        return -1;
    }

    /* parse destination address */
    ipv6_addr_t addr;
    if (ipv6_addr_from_str(&addr, argv[1]) == NULL) {
        LOG_ERROR("send: unable to parse destination address!\n");
        return -2;
    }
    /* parse port */
    uint16_t port = (uint16_t)atoi(argv[2]);
    if (port <= 0) {
        LOG_ERROR("send: unable to parse destination port!\n");
        return -3;
    }
    /* parse num bytes */
    uint32_t bytes = (uint32_t)atoi(argv[3]);
    if (bytes <= 0) {
        LOG_ERROR("send: unable to parse number of bytes to send!");
        return -4;
    }
    uint16_t loops = 1;
    if (argc == 5) {
        loops = (uint16_t)atoi(argv[4]);
        if (loops <= 0) {
            LOG_ERROR("send: unable to parse number of loops!\n");
            return -5;
        }
    }

#ifdef USE_LWIP_TCP
    return _lwip_tcp_send(&addr, port, bytes, loops);
#else
    return _gnrc_tcp_send(&addr, port, bytes, loops);
#endif /* USE_LWIP_TCP */
}

int main(void)
{
    printf("\nTCP, run on port %d and IP addresses:\n", TCP_PORT);
#ifndef USE_LWIP_TCP
    /* get the first IPv6 interface and prints its address */
    kernel_pid_t ifs[GNRC_NETIF_NUMOF];
    size_t numof = gnrc_netif_get(ifs);
    if (numof > 0) {
        gnrc_ipv6_netif_t *entry = gnrc_ipv6_netif_get(ifs[0]);
        char ipv6_addr_str[IPV6_ADDR_MAX_STR_LEN];
        for (int i = 0; i < GNRC_IPV6_NETIF_ADDR_NUMOF; i++) {
            if ((ipv6_addr_is_link_local(&entry->addrs[i].addr)) && !(entry->addrs[i].flags & GNRC_IPV6_NETIF_ADDR_FLAGS_NON_UNICAST)) {
                ipv6_addr_to_str(ipv6_addr_str, &entry->addrs[i].addr, IPV6_ADDR_MAX_STR_LEN);
                printf(" -- %s\n", ipv6_addr_str);
            }
        }
    }
#else
    for (struct netif *iface = netif_list; iface != NULL; iface = iface->next) {
        char addrstr[IPV6_ADDR_MAX_STR_LEN];
        for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
            if (!ipv6_addr_is_unspecified((ipv6_addr_t *)&iface->ip6_addr[i])) {
                printf(" -- %s\n", ipv6_addr_to_str(addrstr, (ipv6_addr_t *)&iface->ip6_addr[i],
                                                       sizeof(addrstr)));
            }
        }
    }
#endif /* USE_LWIP_TCP */
    puts("-----------------------------------------------------------");
    puts("Init shell now!");
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
