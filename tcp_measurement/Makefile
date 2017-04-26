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

USEMODULE += lwip lwip_ipv6_autoconfig lwip_sock_ip lwip_netdev
USEMODULE += lwip_udp lwip_sock_udp
USEMODULE += lwip_tcp lwip_sock_tcp
USEMODULE += ipv6_addr
USEMODULE += od
USEMODULE += netdev_default

ifeq ($(BOARD),native)
  USEMODULE += lwip_ethernet
endif

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
