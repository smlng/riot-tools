# name of your application
APPLICATION = tools_sock_tcp_listen

# If no BOARD is found in the environment, use this default:
BOARD ?= native
PORT ?= tap0

# lwIP's memory management doesn't seem to work on non 32-bit platforms at the
# moment.
BOARD_BLACKLIST := arduino-uno arduino-duemilanove arduino-mega2560 chronos \
                   msb-430 msb-430h telosb waspmote-pro wsn430-v1_3b \
                   wsn430-v1_4 z1
BOARD_INSUFFICIENT_MEMORY = nucleo-f030 nucleo32-f042 nucleo-f334 \
                            stm32f0discovery weio

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
#CFLAGS += -DDEVELHELP

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

# uncomment to change TCP listen port
#CFLAGS += -DTCP_LISTEN_PORT=80

USEMODULE += inet_csum
USEMODULE += ipv6_addr

USEMODULE += lwip_ipv6_autoconfig
USEMODULE += lwip lwip_ipv6_autoconfig lwip_netdev2
USEMODULE += lwip_sock_tcp

# use the at86rf231 as fallback device
DRIVER := at86rf231

# define the driver to be used for selected boards
ifneq (,$(filter samr21-xpro,$(BOARD)))
  DRIVER := at86rf233
endif
ifneq (,$(filter iotlab-m3 fox,$(BOARD)))
  DRIVER := at86rf231
endif
ifneq (,$(filter mulle,$(BOARD)))
  DRIVER := at86rf212b
endif
ifneq (,$(filter native,$(BOARD)))
  DRIVER := netdev2_tap
  USEMODULE += lwip_ethernet
endif

ifneq (,$(filter at86rf2%,$(DRIVER)))
  FEATURES_REQUIRED = periph_spi periph_gpio
endif

USEMODULE += $(DRIVER)

#DISABLE_MODULE += auto_init

CFLAGS += -DDEVELHELP
CFLAGS += -DSO_REUSE
CFLAGS += -DLWIP_SO_RCVTIMEO
CFLAGS += -DLWIP_SOCK_TCP_ACCEPT_TIMEOUT=500
CFLAGS += -DLWIP_NETIF_LOOPBACK=1
CFLAGS += -DLWIP_HAVE_LOOPIF=1

include $(RIOTBASE)/Makefile.include
