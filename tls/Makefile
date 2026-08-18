CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -pedantic
OPENSSL_CFLAGS ?= $(shell pkg-config --cflags openssl)
OPENSSL_LIBS ?= $(shell pkg-config --libs openssl)

.PHONY: all clean check-groups

all: tls_server tls_benchmark

tls_server: tls_server.c common.c common.h
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ tls_server.c common.c $(OPENSSL_LIBS)

tls_benchmark: tls_benchmark.c common.c common.h
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ tls_benchmark.c common.c $(OPENSSL_LIBS)

check-groups:
	openssl list -tls1_3 -tls-groups | tr ':' '\n' | grep -qx X25519MLKEM768

clean:
	rm -f tls_server tls_benchmark

