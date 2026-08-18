#define _POSIX_C_SOURCE 200809L

#include "common.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    int port;
    const char *group;
    const char *mode;
    const char *certificate;
    const char *private_key;
    const char *dashboard_host;
    const char *dashboard_port;
} ServerOptions;

static volatile sig_atomic_t keep_running = 1;

static void stop_server(int signal_number) {
    (void)signal_number;
    keep_running = 0;
}

static void usage(const char *program) {
    fprintf(stderr, "Usage: %s --port PORT --group GROUP --mode classical|hybrid --cert FILE --key FILE --dashboard-host HOST --dashboard-port PORT\n", program);
}

static int parse_options(int argc, char **argv, ServerOptions *options) {
    int index;
    *options = (ServerOptions){
        .port = 4433,
        .group = "X25519",
        .mode = "classical",
        .certificate = "/opt/tls/certs/server.crt",
        .private_key = "/opt/tls/certs/server.key",
        .dashboard_host = "dashboard",
        .dashboard_port = "8000",
    };
    for (index = 1; index < argc; index++) {
        if (index + 1 >= argc) {
            return -1;
        }
        if (strcmp(argv[index], "--port") == 0) options->port = atoi(argv[++index]);
        else if (strcmp(argv[index], "--group") == 0) options->group = argv[++index];
        else if (strcmp(argv[index], "--mode") == 0) options->mode = argv[++index];
        else if (strcmp(argv[index], "--cert") == 0) options->certificate = argv[++index];
        else if (strcmp(argv[index], "--key") == 0) options->private_key = argv[++index];
        else if (strcmp(argv[index], "--dashboard-host") == 0) options->dashboard_host = argv[++index];
        else if (strcmp(argv[index], "--dashboard-port") == 0) options->dashboard_port = argv[++index];
        else return -1;
    }
    if (options->port < 1 || options->port > 65535 ||
        (strcmp(options->mode, "classical") != 0 && strcmp(options->mode, "hybrid") != 0)) {
        return -1;
    }
    return 0;
}

static SSL_CTX *create_context(const ServerOptions *options) {
    SSL_CTX *context = SSL_CTX_new(TLS_server_method());
    if (context == NULL) return NULL;
    if (!SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) ||
        !SSL_CTX_set1_groups_list(context, options->group) ||
        SSL_CTX_use_certificate_file(context, options->certificate, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(context, options->private_key, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(context) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(context);
        return NULL;
    }
    SSL_CTX_set_num_tickets(context, 0);
    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_OFF);
    return context;
}

static int create_listener(int port) {
    int listener = socket(AF_INET6, SOCK_STREAM, 0);
    int enabled = 1;
    int disabled = 0;
    struct sockaddr_in6 address = {0};
    if (listener < 0) return -1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, &disabled, sizeof(disabled));
    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_any;
    address.sin6_port = htons((uint16_t)port);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(listener, 128) != 0) {
        close(listener);
        return -1;
    }
    return listener;
}

static int extract_query_value(const char *request, const char *name, char *output, size_t output_size) {
    char pattern[64];
    const char *start;
    const char *end;
    size_t length;
    snprintf(pattern, sizeof(pattern), "%s=", name);
    start = strstr(request, pattern);
    if (start == NULL) return -1;
    start += strlen(pattern);
    end = start;
    while (*end != '\0' && *end != '&' && *end != ' ' && *end != '\r' && *end != '\n') end++;
    length = (size_t)(end - start);
    if (length == 0 || length >= output_size) return -1;
    memcpy(output, start, length);
    output[length] = '\0';
    return valid_identifier(output) ? 0 : -1;
}

static void handle_connection(SSL_CTX *context, int client_fd, const ServerOptions *options) {
    SSL *ssl = SSL_new(context);
    char request[2048] = {0};
    char sample_id[180] = {0};
    char run_id[140] = {0};
    char response_body[768];
    char response[1400];
    char post_body[1200];
    const char *group_name;
    char negotiated_group[100];
    char tls_version[50];
    char cipher[120];
    int group_id;
    int request_bytes;
    int response_length;
    int record_sample;
    uint64_t started;
    uint64_t completed;
    uint64_t handshake_us;

    if (ssl == NULL) {
        close(client_fd);
        return;
    }
    SSL_set_fd(ssl, client_fd);
    started = now_microseconds();
    if (SSL_accept(ssl) != 1) {
        SSL_free(ssl);
        close(client_fd);
        return;
    }
    completed = now_microseconds();
    handshake_us = completed - started;
    request_bytes = SSL_read(ssl, request, (int)sizeof(request) - 1);
    if (request_bytes <= 0) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        return;
    }
    request[request_bytes] = '\0';
    record_sample = strstr(request, "record=1") != NULL &&
                    extract_query_value(request, "sample_id", sample_id, sizeof(sample_id)) == 0 &&
                    extract_query_value(request, "run_id", run_id, sizeof(run_id)) == 0;
    group_id = SSL_get_negotiated_group(ssl);
    group_name = SSL_group_to_name(ssl, group_id);
    snprintf(negotiated_group, sizeof(negotiated_group), "%s", group_name == NULL ? "unknown" : group_name);
    snprintf(tls_version, sizeof(tls_version), "%s", SSL_get_version(ssl));
    snprintf(cipher, sizeof(cipher), "%s", SSL_get_cipher_name(ssl));
    snprintf(
        response_body,
        sizeof(response_body),
        "{\"sample_id\":\"%s\",\"mode\":\"%s\",\"expected_group\":\"%s\",\"negotiated_group\":\"%s\",\"tls_version\":\"%s\",\"cipher\":\"%s\",\"server_handshake_us\":%llu}",
        sample_id,
        options->mode,
        options->group,
        negotiated_group,
        tls_version,
        cipher,
        (unsigned long long)handshake_us
    );
    response_length = snprintf(
        response,
        sizeof(response),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n%s",
        strlen(response_body),
        response_body
    );
    if (response_length > 0 && (size_t)response_length < sizeof(response)) {
        SSL_write(ssl, response, response_length);
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);

    if (record_sample) {
        snprintf(
            post_body,
            sizeof(post_body),
            "{\"sample_id\":\"%s\",\"run_id\":\"%s\",\"mode\":\"%s\",\"expected_group\":\"%s\",\"negotiated_group\":\"%s\",\"tls_version\":\"%s\",\"cipher\":\"%s\",\"server_handshake_us\":%llu}",
            sample_id,
            run_id,
            options->mode,
            options->group,
            negotiated_group,
            tls_version,
            cipher,
            (unsigned long long)handshake_us
        );
        post_json(options->dashboard_host, options->dashboard_port, "/api/measurements/server", post_body);
    }
}

int main(int argc, char **argv) {
    ServerOptions options;
    SSL_CTX *context;
    int listener;
    if (parse_options(argc, argv, &options) != 0) {
        usage(argv[0]);
        return 2;
    }
    signal(SIGINT, stop_server);
    signal(SIGTERM, stop_server);
    signal(SIGPIPE, SIG_IGN);
    OPENSSL_init_ssl(0, NULL);
    context = create_context(&options);
    if (context == NULL) {
        fprintf(stderr, "failed to create TLS context for group %s\n", options.group);
        return 1;
    }
    listener = create_listener(options.port);
    if (listener < 0) {
        fprintf(stderr, "listen on port %d failed: %s\n", options.port, strerror(errno));
        SSL_CTX_free(context);
        return 1;
    }
    printf("%s TLS endpoint listening on %d with %s (%s)\n", options.mode, options.port, options.group, OpenSSL_version(OPENSSL_VERSION));
    fflush(stdout);
    while (keep_running) {
        int client_fd = accept(listener, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        {
            int enabled = 1;
            setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
        }
        handle_connection(context, client_fd, &options);
    }
    close(listener);
    SSL_CTX_free(context);
    return 0;
}
