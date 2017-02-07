# name of your application
APPLICATION = tools_tcp_listen

# If no BOARD is found in the environment, use this default:
BOARD ?= native
PORT ?= tap0

# Mark Boards with insufficient memory
BOARD_INSUFFICIENT_MEMORY := airfy-beacon arduino-duemilanove arduino-mega2560\
                             arduino-uno calliope-mini chronos microbit sb-430\
                             sb-430h nrf51dongle nrf6310 nucleo-f030 nucleo-f042\
                             nucleo32-f042 nucleo-f070 nucleo-f072 nucleo32-f303\
                             nucleo-f334 pca10000 pca10005 stm32f0discovery\
                             telosb weio wsn430-v1_3b wsn430-v1_4\
                             yunjia-nrf51822 z1 msb-430 msb-430h

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

# Modules to include
USEMODULE += gnrc_netdev_default
USEMODULE += auto_init_gnrc_netif
USEMODULE += gnrc_ipv6_default
USEMODULE += gnrc_tcp
USEMODULE += gnrc_pktdump

include $(RIOTBASE)/Makefile.include
