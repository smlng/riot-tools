/*
 * Copyright (C) 2016 smlng
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include "lwip.h"
#include "lwip/netif.h"
#include "net/ipv6/addr.h"
#include "net/sock/tcp.h"

#define ENABLE_DEBUG (1)
#include "debug.h"

// the port to listen for tcp connections
#ifndef TCP_LISTEN_PORT
#define TCP_LISTEN_PORT     (24911U)
#endif
// length of buffer for tcp receive
#define TCP_LISTEN_BUFLEN   (512U)
// timeout in usec for tcp receive
#define TCP_LISTEN_TIMEOUT  (GNRC_TCP_CONNECTION_TIMEOUT_DURATION)
// max num of errors, before exit
#define MAX_ERROR_COUNT     (100U)
#define TCP_QUEUE_SIZE  (1)

#define TCP_NETIF           (1)
#define TCP_ADDR6_LOCAL     { 0x2f, 0xc4, 0x11, 0x5a, 0xe6, 0x91, 0x8d, 0x5d, \
                              0x8c, 0xd1, 0x47, 0x07, 0xb7, 0x6f, 0x9b, 0x48 }
#define TCP_LLADDR_STR        ("fe80::cafe:cafe:cafe:42")

int listen(uint16_t port)
{
    sock_tcp_queue_t queue;
    sock_tcp_t queue_array[TCP_QUEUE_SIZE];
    ipv6_addr_t addr;
    if (ipv6_addr_from_str(&addr, TCP_LLADDR_STR) == NULL) {
        puts("[ERROR] unable to parse link local address");
        return 42;
    }
    sock_tcp_ep_t local;
    memset(&local, 0, sizeof(local));
    local.family = AF_INET6;
    local.port = port;
    local.netif = SOCK_ADDR_ANY_NETIF;
    memcpy((void *)&local.addr.ipv6, (void *)&addr.u8, sizeof(addr));
    /* open listing port */
    if (0 != sock_tcp_listen(&queue, &local, queue_array, TCP_QUEUE_SIZE,
                             SOCK_FLAGS_REUSE_EP)) {
        puts("[ERROR] sock_tcp_listen!");
        return 1;
    }
    puts("[SUCCESS] sock_tcp_listen \n");
    /* waiting for connection */
    sock_tcp_t *sock = NULL;
    if (0 != sock_tcp_accept(&queue, &sock, SOCK_NO_TIMEOUT)) {
        puts("[ERROR] sock_tcp_accept!");
        return 2;
    }
    puts("[SUCCESS] sock_tcp_accept");
    /* got a connection, start receiving */
    uint8_t buf[TCP_LISTEN_BUFLEN];
    unsigned errcnt = 0;
    while (errcnt < MAX_ERROR_COUNT) {
        memset(buf, 0, TCP_LISTEN_BUFLEN);
        if (sock_tcp_read(sock, buf, (TCP_LISTEN_BUFLEN-1), SOCK_NO_TIMEOUT) > 0) {
            printf("received message: %s\n", buf);
        }
        else {
            ++errcnt;
        }
    }
    puts("[ERROR] stop listening, too many errors!");
    /* close connection and cleanup */
    sock_tcp_disconnect(sock);
    sock = NULL;
    sock_tcp_stop_listen(&queue);
    return 0;
}

int main(void)
{
    printf("\nStarting TCP server, listening on port %d\n and IP addresses:\n", TCP_LISTEN_PORT);
    for (struct netif *iface = netif_list; iface != NULL; iface = iface->next) {
        printf("%s_%02u: ", iface->name, iface->num);
        #ifdef MODULE_LWIP_IPV6
        char addrstr[IPV6_ADDR_MAX_STR_LEN];
        for (int i = 0; i < LWIP_IPV6_NUM_ADDRESSES; i++) {
            if (!ipv6_addr_is_unspecified((ipv6_addr_t *)&iface->ip6_addr[i])) {
                printf(" inet6 %s\n", ipv6_addr_to_str(addrstr, (ipv6_addr_t *)&iface->ip6_addr[i],
                                                   sizeof(addrstr)));
           }
        }
        #endif
        puts("");
    }
    puts("-------------------------------------------------------------------");
    return listen(TCP_LISTEN_PORT);
}
