#ifdef USE_LWIP_TCP
#include "lwip.h"
#include "lwip/netif.h"
#include "net/ipv6/addr.h"
#include "net/sock/tcp.h"

#include "measurement.h"

static sock_tcp_t _sock;
/*
static sock_tcp_t _queue_array[_QUEUE_SIZE];
static sock_tcp_t _server_queue_array[_SERVER_QUEUE_SIZE];
static sock_tcp_queue_t _queue, _server_queue;
static sock_tcp_ep_t _server_addr;
*/

int _lwip_tcp_recv(uint16_t port, uint32_t bytes, uint16_t loops)
{
    (void) port;
    (void) bytes;
    (void) loops;
    return 0;
}

int _lwip_tcp_send(const ipv6_addr_t *addr, uint16_t port, uint32_t bytes, uint16_t loops)
{
    (void) addr;
    (void) port;
    (void) bytes;
    (void) loops;
    sock_tcp_ep_t remote = {    .family = AF_INET6,
                                .port   = port,
                                .netif  = SOCK_ADDR_ANY_NETIF };
    memcpy(&remote.addr, addr, sizeof(ipv6_addr_t));
    int ret = sock_tcp_connect(&_sock, &remote, 0, SOCK_FLAGS_REUSE_EP);
    if (ret < 0) {
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
            ret = sock_tcp_write(&_sock, buf , MIN(TCP_BUFLEN, send_bytes));
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
    sock_tcp_disconnect(&_sock);
    return 0;
}
#else
typedef int dont_be_pedantic;
#endif /* USE_LWIP_TCP */
