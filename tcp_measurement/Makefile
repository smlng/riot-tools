# name of your application
APPLICATION = tcp_measurement

# If no BOARD is found in the environment, use this default:
BOARD ?= native
PORT ?= tap0

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

USE_LWIP_TCP ?= 0

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
#CFLAGS += -DDEVELHELP

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

ifneq (0, $(USE_LWIP_TCP))
# settings for lwip tcp
CFLAGS += -DUSE_LWIP_TCP

USEMODULE += ipv6_addr
USEMODULE += lwip_ipv6_autoconfig

USEMODULE += inet_csum
USEMODULE += lwip_ethernet lwip_netdev
USEMODULE += lwip_sock_tcp
USEMODULE += netdev_tap

DISABLE_MODULE += auto_init

CFLAGS += -DDEVELHELP
CFLAGS += -DSO_REUSE
CFLAGS += -DLWIP_SO_RCVTIMEO
else
# settings for gnrc tcp
USEMODULE += gnrc_netdev_default
USEMODULE += auto_init_gnrc_netif
USEMODULE += gnrc_ipv6_default
USEMODULE += gnrc_tcp
endif
# common modules
USEMODULE += shell

include $(RIOTBASE)/Makefile.include
