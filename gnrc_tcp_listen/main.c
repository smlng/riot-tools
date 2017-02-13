/*
 * Copyright (C) 2016 smlng
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include "net/af.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/tcp.h"

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

int listen(uint16_t port)
{
    unsigned errcnt = 0;
    gnrc_tcp_tcb_t tcb;
    while (errcnt < MAX_ERROR_COUNT) {
        gnrc_tcp_tcb_init(&tcb);
        DEBUG("[SUCCESS] Initialized TCB.\n");
        /* open listening port */
        if (gnrc_tcp_open_passive(&tcb, AF_INET6, NULL, port) != 0) {
            puts("[ERROR] gnrc_tcp_open_passive!\n");
            return 1;
        }
        DEBUG("[SUCCESS] opened passive connection, waiting for connection ...\n");
        uint8_t buf[TCP_LISTEN_BUFLEN];
        /* receive loop */
        while(1) {
            memset(buf, 0, TCP_LISTEN_BUFLEN);
            if(gnrc_tcp_recv(&tcb, (void *)buf, (TCP_LISTEN_BUFLEN-1),
                             (TCP_LISTEN_TIMEOUT)) < 0) {
                puts("[ERROR] gnrc_tcp_recv, reset connection ...");
                break;
            }
            /* got something */
            printf("received message: %s\n", buf);
        }
        ++errcnt;
        /* close connection and cleanup */
        gnrc_tcp_close(&tcb);
    }
    printf("[INFO] stop listening, connection limit (%d)!\n", MAX_ERROR_COUNT);
    return 0;
}

int main(void)
{
    printf("\nStarting TCP server, listening on port %d and IP addresses:\n", TCP_LISTEN_PORT);

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
    puts("-----------------------------------------------------------");
    return listen(TCP_LISTEN_PORT);
}
