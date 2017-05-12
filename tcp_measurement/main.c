/*
 * Copyright (C) 2017 smlng
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */


#include <stdio.h>
#include <stdlib.h>

#include "kernel_types.h"
#include "log.h"
#include "net/af.h"
#include "net/gnrc/ipv6.h"
#include "net/ipv6/addr.h"
#include "sched.h"
#include "shell.h"
#include "thread.h"
#include "xtimer.h"

#ifdef USE_LWIP_TCP
#include "lwip.h"
#include "lwip/netif.h"
#include "net/sock/tcp.h"

#define LWIP_SOCK_INBUF_SIZE        (256)
#define LWIP_SERVER_MSG_QUEUE_SIZE  (8)
#define LWIP_SERVER_BUFFER_SIZE     (64)
#define LWIP_LOCAL_PORT             (4614)

static sock_tcp_t server_sock;
static sock_tcp_t client_sock;
static sock_tcp_queue_t server_queue;
static msg_t server_msg_queue[LWIP_SERVER_MSG_QUEUE_SIZE];

#else /* that is GNRC TCP */

#define GNRC_TCP_TIMEOUT                        (30U * US_PER_SEC)
#define GNRC_TCP_CONNECTION_TIMEOUT_DURATION    (GNRC_TCP_TIMEOUT)
#include "net/gnrc/tcp.h"

#endif /* USE_LWIP_TCP */

#define MIN(a, b)                   ((a > b) ? b : a)

// the port to listen for tcp connections
#ifndef TCP_PORT
#define TCP_PORT                    (24911U)
#endif
// length of buffer for tcp receive
#define TCP_BUFLEN                  (8 * 1024U) /* 8K default */
#define TCP_TEST_DEFSIZE            (1220U)     /* default send/recv size */
#define TCP_TEST_DEFCOUNT           (1000U)     /* default send/recv count */
#define TCP_TEST_PATTERN            (66U)       /* HEX = 0x42 */
#define TCP_TEST_STATVAL            (100U)      /* print stats every N send/recv */

#define MAIN_QUEUE_SIZE             (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

static int tcp_recv(int argc, char **argv);
static int tcp_send(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    { "listen", "receive TCP", tcp_recv },
    { "send", "send TCP", tcp_send },
    { NULL, NULL, NULL }
};

static uint8_t buf[TCP_BUFLEN];

static void print_stats(uint32_t bytes, uint64_t diff_us, unsigned count)
{
    printf("%"PRIu32",%"PRIu64",%u", bytes, diff_us, count);
#ifdef DEVELHELP
    for (kernel_pid_t i = KERNEL_PID_FIRST; i <= KERNEL_PID_LAST; i++) {
        thread_t *p = (thread_t *)sched_threads[i];
        if (p != NULL) {
            int mem = p->stack_size - thread_measure_stack_free(p->stack_start);
            printf(",%"PRIkernel_pid",%s,%d", p->pid, p->name, mem);
#ifdef MODULE_SCHEDSTATISTICS
            uint64_t now = _xtimer_now64();
            uint64_t runtime_ticks = sched_pidlist[i].runtime_ticks;
            /* add ticks since laststart not accounted for yet */
            if (thread_getpid() == i) {
                runtime_ticks += now - sched_pidlist[i].laststart;
            }
            printf(",%"PRIu64"", runtime_ticks);
#else
            printf(",0");
#endif
        }
    }
#endif
    puts("");
}

static int tcp_recv(int argc, char **argv)
{
    uint32_t bytes = TCP_TEST_DEFSIZE;
    uint32_t count = TCP_TEST_DEFCOUNT;
    if ((argc < 2) || (argc > 4)) {
        puts("usage: listen PORT [SIZE] [COUNT]");
        printf("    listen on PORT with buffer of SIZE (%dB)\n", TCP_TEST_DEFSIZE);
        printf("    and stop after COUNT (%d) receive calls.\n", TCP_TEST_DEFCOUNT);
        return -1;
    }
    /* parse port */
    uint16_t port = (uint16_t)strtoul(argv[1], NULL, 10);
    if (port == 0) {
        LOG_ERROR("recv: unable to parse listen port!\n");
        return -3;
    }
    /* parse num bytes */
    if (argc > 2) {
        bytes = (uint32_t)strtoul(argv[2], NULL, 10);
        if (bytes == 0) {
            LOG_WARNING("recv: invalid bytes or 0, default to max!\n");
            bytes = UINT32_MAX;
        }
    }
    /* parse count */
    if (argc == 4) {
        count = (uint16_t)strtoul(argv[3], NULL, 10);
        if (count == 0) {
            LOG_WARNING("recv: invalid count value or 0, default to max!\n");
            count = UINT32_MAX;
        }
    }
    int ret = -42;
    /* start listening */
#ifdef USE_LWIP_TCP
    sock_tcp_ep_t server_addr = SOCK_IPV6_EP_ANY;
    server_addr.port = port;
    msg_init_queue(server_msg_queue, LWIP_SERVER_MSG_QUEUE_SIZE);
    ret = sock_tcp_listen(&server_queue, &server_addr, &server_sock, 1, 0);
    if (ret != 0) {
        LOG_ERROR("[ERROR] LWIP sock_tcp_listen failed!\n");
        return -5;
    }
    LOG_INFO("[SUCCESS] LWIP waiting for connections ...\n");
    sock_tcp_t *sock = NULL;
    ret = sock_tcp_accept(&server_queue, &sock, SOCK_NO_TIMEOUT);
#else
    gnrc_tcp_tcb_t tcb;
    gnrc_tcp_tcb_init(&tcb);
    LOG_INFO("[SUCCESS] Initialized TCB.\n");
    /* open listening port */
    ret = gnrc_tcp_open_passive(&tcb, AF_INET6, NULL, port);
#endif /* USE_LWIP_TCP */
    if (ret != 0) {
        LOG_ERROR("[ERROR] failed to accept connection!\n");
        return -6;
    }
    LOG_INFO("[SUCCESS] accepted connection.\n");
    uint64_t now, begin;
    uint32_t recv_bytes = 0;
    uint64_t diff_us = 0;
    unsigned recv_count = 0;
    begin = xtimer_now_usec64();
    /* receive loop */
    while (recv_count < count) {
        uint32_t bytes_remain = bytes;
        while (bytes_remain > 0) {
#ifdef USE_LWIP_TCP
            ret = sock_tcp_read(sock, (char *)buf, MIN(TCP_BUFLEN, bytes_remain), SOCK_NO_TIMEOUT);
#else
            ret = gnrc_tcp_recv(&tcb, (void *)buf, MIN(TCP_BUFLEN, bytes_remain), GNRC_TCP_TIMEOUT);
#endif /* USE_LWIP_TCP */
            if (ret < 0) {
                break;
            }
            recv_bytes += ret;
            bytes_remain -= ret;
        }

        if (ret < 0) {
            puts("error, failed to receive!");
            break;
        }

        ++recv_count;
        if (recv_count % TCP_TEST_STATVAL == 0) {
            now = xtimer_now_usec64();
            diff_us = now - begin;
            print_stats(recv_bytes, diff_us, recv_count);
        }
    }
    if (recv_count < count) { /* error in loop */
        now = xtimer_now_usec64();
        diff_us = now - begin;
        print_stats(recv_bytes, diff_us, recv_count);
    }
    /* close connection and cleanup anyway */
#ifdef USE_LWIP_TCP
    sock_tcp_disconnect(sock);
#else
    gnrc_tcp_close(&tcb);
#endif /* USE_LWIP_TCP */
    LOG_INFO("[SUCCESS] Closed TCP connection.\n");
    return 0;
}

static int tcp_send(int argc, char **argv)
{
    uint32_t bytes = TCP_TEST_DEFSIZE;
    uint32_t count = TCP_TEST_DEFCOUNT;

    if ((argc < 2) || (argc > 5)) {
        puts("usage: send ADDR PORT [SIZE] [COUNT]");
        printf("    send to ADDR on PORT with buffer of SIZE (%dB)\n", TCP_TEST_DEFSIZE);
        printf("    and stop after COUNT (%d) send calls.\n2", TCP_TEST_DEFCOUNT);
        return -1;
    }

    /* parse destination address */
    ipv6_addr_t addr;
    if (ipv6_addr_from_str(&addr, argv[1]) == NULL) {
        LOG_ERROR("send: unable to parse destination address!\n");
        return -2;
    }
    /* parse port */
    uint16_t port = (uint16_t)strtoul(argv[2], NULL, 10);
    if (port == 0) {
        LOG_ERROR("send: unable to parse destination port!\n");
        return -3;
    }
    /* parse num bytes */
    if (argc > 3) {
        bytes = (uint32_t)strtoul(argv[3], NULL, 10);
        if (bytes == 0) {
            LOG_WARNING("send: invalid bytes or 0, default to max!\n");
            bytes = UINT32_MAX;
        }
    }
    /* parse count */
    if (argc == 5) {
        count = (uint16_t)strtoul(argv[4], NULL, 10);
        if (count == 0) {
            LOG_WARNING("send: invalid count value or 0, default to max!\n");
            count = UINT32_MAX;
        }
    }
    int ret = -42;
#ifdef USE_LWIP_TCP
    sock_tcp_ep_t dst = SOCK_IPV6_EP_ANY;
    dst.port = port;
    memcpy(&dst.addr.ipv6,&addr,sizeof(ipv6_addr_t));
    //uint16_t local_port = LWIP_LOCAL_PORT;
    ret = sock_tcp_connect(&client_sock, &dst, 0, 0);
#else
    gnrc_tcp_tcb_t tcb;
    gnrc_tcp_tcb_init(&tcb);
    LOG_INFO("[SUCCESS] Initialized TCB.\n");
    ret = gnrc_tcp_open_active(&tcb, AF_INET6, (uint8_t *) &addr, port, 0);
#endif
    if (ret != 0) {
        LOG_ERROR("[ERROR] failed to open active connection!\n");
        return -6;
    }
    LOG_INFO("[SUCCESS] opened TCP connection, start sending.\n");

    memset(buf, TCP_TEST_PATTERN, TCP_BUFLEN);
    uint64_t now, begin;
    uint32_t send_bytes = 0;
    uint64_t diff_us = 0;
    unsigned send_count = 0;
    begin = xtimer_now_usec64();
    while (send_count < count) {
        uint32_t bytes_remain = bytes;
        while (bytes_remain > 0) {
#ifdef USE_LWIP_TCP
            ret = sock_tcp_write(&client_sock, buf, MIN(TCP_BUFLEN, bytes_remain));
#else
            ret = gnrc_tcp_send(&tcb, buf, MIN(TCP_BUFLEN, bytes_remain), 0);
#endif /* USE_LWIP_TCP */
            if (ret < 0) {
                break;
            }
            send_bytes += ret;
            bytes_remain -= ret;
        }

        if (ret < 0) {
            puts("error, failed to send!");
            break;
        }

        ++send_count;
        if (send_count % TCP_TEST_STATVAL == 0) {
            now = xtimer_now_usec64();
            diff_us = now - begin;
            print_stats(send_bytes, diff_us, send_count);
        }
    }
    if (send_count < count) { /* error in loop */
        now = xtimer_now_usec64();
        diff_us = now - begin;
        print_stats(send_bytes, diff_us, send_count);
    }
    /* close connection and cleanup anyway */
#ifdef USE_LWIP_TCP
    sock_tcp_disconnect(&client_sock);
#else
    gnrc_tcp_close(&tcb);
#endif /* USE_LWIP_TCP */
    LOG_INFO("[SUCCESS] Closed TCP connection.\n");
    return 0;
}

int main(void)
{
    puts("\nTCP will listen on IP addresses:\n");
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
