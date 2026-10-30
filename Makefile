CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -O2

SOURCES = src/main.c src/arp_parsing.c src/helpers.c src/packet_loggin.c \
	src/quic_parsing.c src/statistic.c src/tls_parsing.c src/port_lock.c

netwatch: $(SOURCES) $(wildcard include/*.h)
	$(CC) $(CFLAGS) $(SOURCES) -o $@ -lcrypto
