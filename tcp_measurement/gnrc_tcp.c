#ifndef USE_LWIP_TCP

#include <stdio.h>
#include <stdlib.h>

#include "log.h"
#include "net/af.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/tcp.h"
#include "xtimer.h"

#include "measurement.h"

// timeout in usec for tcp receive
#define TCP_TIMEOUT  (GNRC_TCP_CONNECTION_TIMEOUT_DURATION)

int _gnrc_tcp_recv(uint16_t port, uint32_t bytes, uint16_t loops)
{
    gnrc_tcp_tcb_t tcb;
    gnrc_tcp_tcb_init(&tcb);
    LOG_INFO("[SUCCESS] Initialized TCB.\n");
    /* open listening port */
    if (gnrc_tcp_open_passive(&tcb, AF_INET6, NULL, port) != 0) {
        puts("[ERROR] gnrc_tcp_open_passive!\n");
        return -1;
    }
    LOG_INFO("[SUCCESS] passive TCP connection, waiting for connections ...\n");
    uint64_t begin, until;
    while (loops > 0) {
        uint32_t recv_bytes = 0;
        unsigned recv_count = 0;
        begin = xtimer_now_usec64();
        /* receive loop */
        while(recv_bytes < bytes) {
            int ret = gnrc_tcp_recv(&tcb, (void *)buf, MIN(TCP_BUFLEN, bytes), (TCP_TIMEOUT));
            if (ret < 0) {
                puts("error, failed to receive!");
                break;
            }
            recv_bytes += ret;
            ++recv_count;
        }
        until = xtimer_now_usec64();
        uint64_t runtime_us = until - begin;
        printf("%"PRIu32",%"PRIu64",%u\n", bytes, runtime_us, recv_count);
        --loops;
    }
    /* close connection and cleanup anyway */
    gnrc_tcp_close(&tcb);
    LOG_INFO("[SUCCESS] Closed TCP connection.\n");
    return 0;
}

int _gnrc_tcp_send(const ipv6_addr_t *addr, uint16_t port, uint32_t bytes, uint16_t loops)
{
    static gnrc_tcp_tcb_t tcb;
    gnrc_tcp_tcb_init(&tcb);
    LOG_INFO("[SUCCESS] Initialized TCB.\n");

    int ret = gnrc_tcp_open_active(&tcb, AF_INET6, (uint8_t *) addr, port, 0);
    if (ret != 0) {
        LOG_ERROR("send: failed to open connection!\n");
        return -6;
    }
    LOG_INFO("[SUCCESS] active TCP connection opened.\n");

    memset(buf, TCP_TEST_PATTERN, TCP_BUFLEN);
    uint64_t begin, until;
    while (loops > 0) {
        uint32_t send_bytes = bytes;
        unsigned send_count = 0;
        begin = xtimer_now_usec64();
        while (send_bytes > 0) {
            ret = gnrc_tcp_send(&tcb, buf , MIN(TCP_BUFLEN, send_bytes), 0);
            if (ret < 0) {
                puts("error, failed to send!");
                break;
            }
            send_bytes -= ret;
            ++send_count;
        }
        until = xtimer_now_usec64();
        uint64_t runtime_us = until - begin;
        printf("%"PRIu32",%"PRIu64",%u\n", bytes, runtime_us, send_count);
        --loops;
    }
    /* close connection and cleanup anyway */
    gnrc_tcp_close(&tcb);
    LOG_INFO("[SUCCESS] Closed TCP connection.\n");
    return 0;
}
#else
typedef int dont_be_pedantic;
#endif /* ! USE_LWIP_TCP */
