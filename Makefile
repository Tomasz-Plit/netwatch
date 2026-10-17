CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -O2

netwatch: src/main.c
	$(CC) $(CFLAGS) $^ -o $@ -lcrypto