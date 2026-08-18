#ifndef HYBRID_TLS_COMMON_H
#define HYBRID_TLS_COMMON_H

#include <stddef.h>
#include <stdint.h>

uint64_t now_microseconds(void);
int tcp_connect_host(const char *host, const char *port, char *error, size_t error_size);
int post_json(const char *host, const char *port, const char *path, const char *json);
void json_escape(const char *input, char *output, size_t output_size);
int valid_identifier(const char *value);

#endif

