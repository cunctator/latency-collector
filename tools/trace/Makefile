# SPDX-License-Identifier: GPL-2.0
# Makefile for vm tools
#
TARGETS = latency-collector
CFLAGS = -Wall -Wextra -g -O2
LDFLAGS = -lpthread

all: $(TARGETS)

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	$(RM) latency-collector

sbindir ?= /usr/sbin

install: all
	install -d $(DESTDIR)$(sbindir)
	install -m 755 -p $(TARGETS) $(DESTDIR)$(sbindir)
