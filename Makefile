CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -O2

SOURCES = src/main.c src/arp_parsing.c src/helpers.c src/packet_loggin.c \
	src/quic_parsing.c src/statistic.c src/tls_parsing.c src/port_lock.c src/tcp_track.c src/tls_json.c src/packet_json.c

netwatch: $(SOURCES) $(wildcard include/*.h)
	$(CC) $(CFLAGS) $(SOURCES) -o $@ -lcrypto

.PHONY: app test test-shutdown
app: netwatch
	python3 app/main.py

test: test-shutdown
	@set -eu; dir=$$(mktemp -d); trap 'rm -rf "$$dir"' EXIT; \
	for name in test_ipv6 test_port_filter test_tls_flow test_tls_metadata test_packet_json test_quic_ack; do \
		$(CC) $(CFLAGS) tests/$$name.c $(filter-out src/main.c,$(SOURCES)) -o "$$dir/$$name" -lcrypto; \
		"$$dir/$$name"; \
		echo "$$name passed"; \
	done
	python3 -m unittest discover -s app -p 'test_*.py'

test-shutdown:
	$(CC) $(CFLAGS) -Dmain=netwatch_main -c src/main.c -o /tmp/netwatch-test-main.o
	$(CC) $(CFLAGS) tests/test_shutdown.c /tmp/netwatch-test-main.o $(filter-out src/main.c,$(SOURCES)) -Wl,--wrap=find_default_interface -Wl,--wrap=open_raw_socket -Wl,--wrap=setsockopt -Wl,--wrap=recieve_packet -o /tmp/netwatch-test-shutdown -lcrypto
	/tmp/netwatch-test-shutdown
