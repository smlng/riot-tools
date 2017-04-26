#include <stdio.h>
#include <stdlib.h>

#include "log.h"
#include "net/af.h"
#include "net/ipv6/addr.h"
#include "xtimer.h"

#ifndef MEASUREMENT_H
#define MEASUREMENT_H

#define MIN(a, b)            ((a > b) ? b : a)

// the port to listen for tcp connections
#ifndef TCP_PORT
#define TCP_PORT            (24911U)
#endif
// length of buffer for tcp receive
#define TCP_BUFLEN          (8 * 1024U)
#define TCP_TEST_PATTERN    (66U)   /* HEX = 0x42 */

extern uint8_t buf[];

#endif /* MEASUREMENT_H */
