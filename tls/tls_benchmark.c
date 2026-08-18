#define _POSIX_C_SOURCE 200809L

#include "common.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    const char *host;
    const char *port;
    const char *group;
    const char *mode;
} Endpoint;

typedef struct {
    Endpoint classical;
    Endpoint hybrid;
    const char *dashboard_host;
    const char *dashboard_port;
    const char *ca_file;
    const char *run_id;
    int iterations;
    int warmup;
} ClientOptions;

static void usage(const char *program) {
    fprintf(stderr, "Usage: %s [--classical-host HOST] [--classical-port PORT] [--hybrid-host HOST] [--hybrid-port PORT] [--dashboard-host HOST] [--dashboard-port PORT] [--cafile FILE] [--iterations N] [--warmup N] [--run-id ID]\n", program);
}

static void default_run_id(char *output, size_t output_size) {
    time_t now = time(NULL);
    struct tm value;
    gmtime_r(&now, &value);
    strftime(output, output_size, "run-%Y%m%dT%H%M%SZ", &value);
    snprintf(output + strlen(output), output_size - strlen(output), "-%ld", (long)getpid());
}

static int parse_options(int argc, char **argv, ClientOptions *options, char *generated_run_id, size_t run_id_size) {
    int index;
    default_run_id(generated_run_id, run_id_size);
    *options = (ClientOptions){
        .classical = {.host = "classical-tls", .port = "4433", .group = "X25519", .mode = "classical"},
        .hybrid = {.host = "hybrid-tls", .port = "4434", .group = "X25519MLKEM768", .mode = "hybrid"},
        .dashboard_host = "dashboard",
        .dashboard_port = "8000",
        .ca_file = "/opt/tls/certs/server.crt",
        .run_id = generated_run_id,
        .iterations = 100,
        .warmup = 10,
    };
    for (index = 1; index < argc; index++) {
        if (index + 1 >= argc) return -1;
        if (strcmp(argv[index], "--classical-host") == 0) options->classical.host = argv[++index];
        else if (strcmp(argv[index], "--classical-port") == 0) options->classical.port = argv[++index];
        else if (strcmp(argv[index], "--hybrid-host") == 0) options->hybrid.host = argv[++index];
        else if (strcmp(argv[index], "--hybrid-port") == 0) options->hybrid.port = argv[++index];
        else if (strcmp(argv[index], "--dashboard-host") == 0) options->dashboard_host = argv[++index];
        else if (strcmp(argv[index], "--dashboard-port") == 0) options->dashboard_port = argv[++index];
        else if (strcmp(argv[index], "--cafile") == 0) options->ca_file = argv[++index];
        else if (strcmp(argv[index], "--iterations") == 0) options->iterations = atoi(argv[++index]);
        else if (strcmp(argv[index], "--warmup") == 0) options->warmup = atoi(argv[++index]);
        else if (strcmp(argv[index], "--run-id") == 0) options->run_id = argv[++index];
        else return -1;
    }
    if (options->iterations < 1 || options->iterations > 1000000 || options->warmup < 0 || options->warmup > 100000 || !valid_identifier(options->run_id)) return -1;
    return 0;
}

static SSL_CTX *create_context(const Endpoint *endpoint, const char *ca_file) {
    SSL_CTX *context = SSL_CTX_new(TLS_client_method());
    if (context == NULL) return NULL;
    if (!SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) ||
        !SSL_CTX_set1_groups_list(context, endpoint->group) ||
        SSL_CTX_load_verify_locations(context, ca_file, NULL) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(context);
        return NULL;
    }
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_OFF);
    return context;
}

static void last_tls_error(char *output, size_t output_size) {
    unsigned long code = ERR_get_error();
    if (code == 0) snprintf(output, output_size, "TLS operation failed");
    else ERR_error_string_n(code, output, output_size);
}

static int record_client(
    const ClientOptions *options,
    const Endpoint *endpoint,
    const char *sample_id,
    const char *negotiated_group,
    const char *tls_version,
    const char *cipher,
    uint64_t tcp_us,
    uint64_t handshake_us,
    uint64_t ttfb_us,
    uint64_t total_us,
    size_t bytes_sent,
    size_t bytes_received,
    int success,
    const char *error
) {
    char escaped_error[1024];
    char error_field[1100];
    char json[2600];
    json_escape(error, escaped_error, sizeof(escaped_error));
    if (success) snprintf(error_field, sizeof(error_field), "null");
    else snprintf(error_field, sizeof(error_field), "\"%s\"", escaped_error);
    snprintf(
        json,
        sizeof(json),
        "{\"sample_id\":\"%s\",\"run_id\":\"%s\",\"mode\":\"%s\",\"expected_group\":\"%s\",\"negotiated_group\":\"%s\",\"tls_version\":\"%s\",\"cipher\":\"%s\",\"client_tcp_us\":%llu,\"client_handshake_us\":%llu,\"client_ttfb_us\":%llu,\"client_total_us\":%llu,\"bytes_sent\":%zu,\"bytes_received\":%zu,\"success\":%s,\"error\":%s}",
        sample_id,
        options->run_id,
        endpoint->mode,
        endpoint->group,
        negotiated_group,
        tls_version,
        cipher,
        (unsigned long long)tcp_us,
        (unsigned long long)handshake_us,
        (unsigned long long)ttfb_us,
        (unsigned long long)total_us,
        bytes_sent,
        bytes_received,
        success ? "true" : "false",
        error_field
    );
    return post_json(options->dashboard_host, options->dashboard_port, "/api/measurements/client", json);
}

static int probe(
    const ClientOptions *options,
    const Endpoint *endpoint,
    SSL_CTX *context,
    int sequence,
    int record
) {
    char sample_id[180];
    char connection_error[512] = {0};
    char request[640];
    char response[4096];
    char group_copy[100] = {0};
    char version_copy[50] = {0};
    char cipher_copy[120] = {0};
    int socket_fd = -1;
    SSL *ssl = NULL;
    uint64_t started = now_microseconds();
    uint64_t connected = started;
    uint64_t handshake_done = started;
    uint64_t first_byte = 0;
    uint64_t completed = started;
    size_t bytes_sent = 0;
    size_t bytes_received = 0;
    int success = 0;
    int group_id;
    int response_offset = 0;
    int read_result;

    snprintf(sample_id, sizeof(sample_id), "%s-%s-%06d", options->run_id, endpoint->mode, sequence);
    socket_fd = tcp_connect_host(endpoint->host, endpoint->port, connection_error, sizeof(connection_error));
    connected = now_microseconds();
    if (socket_fd < 0) goto finished;
    ssl = SSL_new(context);
    if (ssl == NULL) {
        snprintf(connection_error, sizeof(connection_error), "SSL_new failed");
        goto finished;
    }
    SSL_set_fd(ssl, socket_fd);
    SSL_set_tlsext_host_name(ssl, endpoint->host);
    SSL_set1_host(ssl, endpoint->host);
    if (SSL_connect(ssl) != 1) {
        last_tls_error(connection_error, sizeof(connection_error));
        handshake_done = now_microseconds();
        goto finished;
    }
    handshake_done = now_microseconds();
    group_id = SSL_get_negotiated_group(ssl);
    {
        const char *group_name = SSL_group_to_name(ssl, group_id);
        snprintf(group_copy, sizeof(group_copy), "%s", group_name == NULL ? "unknown" : group_name);
    }
    snprintf(version_copy, sizeof(version_copy), "%s", SSL_get_version(ssl));
    snprintf(cipher_copy, sizeof(cipher_copy), "%s", SSL_get_cipher_name(ssl));
    if (strcasecmp(group_copy, endpoint->group) != 0) {
        snprintf(connection_error, sizeof(connection_error), "negotiated %s instead of %s", group_copy, endpoint->group);
        goto finished;
    }
    snprintf(
        request,
        sizeof(request),
        "GET /probe?sample_id=%s&run_id=%s&record=%d HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
        sample_id,
        options->run_id,
        record,
        endpoint->host
    );
    if (SSL_write(ssl, request, (int)strlen(request)) <= 0) {
        last_tls_error(connection_error, sizeof(connection_error));
        goto finished;
    }
    while ((read_result = SSL_read(ssl, response + response_offset, (int)sizeof(response) - response_offset - 1)) > 0) {
        if (first_byte == 0) first_byte = now_microseconds();
        response_offset += read_result;
        if ((size_t)response_offset >= sizeof(response) - 1) break;
    }
    response[response_offset] = '\0';
    if (first_byte == 0 || strstr(response, "HTTP/1.1 200 OK") == NULL) {
        snprintf(connection_error, sizeof(connection_error), "TLS endpoint returned no valid HTTP response");
        goto finished;
    }
    success = 1;

finished:
    completed = now_microseconds();
    if (ssl != NULL) {
        BIO *read_bio = SSL_get_rbio(ssl);
        BIO *write_bio = SSL_get_wbio(ssl);
        if (read_bio != NULL) bytes_received = (size_t)BIO_number_read(read_bio);
        if (write_bio != NULL) bytes_sent = (size_t)BIO_number_written(write_bio);
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (socket_fd >= 0) close(socket_fd);
    if (record) {
        record_client(
            options,
            endpoint,
            sample_id,
            group_copy,
            version_copy,
            cipher_copy,
            connected - started,
            handshake_done >= connected ? handshake_done - connected : 0,
            first_byte ? first_byte - started : 0,
            completed - started,
            bytes_sent,
            bytes_received,
            success,
            connection_error
        );
        printf("%-9s %4d/%d  TLS %8.3f ms  total %8.3f ms  %s\n", endpoint->mode, sequence, options->iterations, (double)(handshake_done - connected) / 1000.0, (double)(completed - started) / 1000.0, success ? "OK" : connection_error);
        fflush(stdout);
    }
    return success ? 0 : -1;
}

int main(int argc, char **argv) {
    ClientOptions options;
    char generated_run_id[128];
    char run_json[1200];
    char version_escaped[500];
    char complete_path[300];
    SSL_CTX *classical_context;
    SSL_CTX *hybrid_context;
    int index;
    int failures = 0;
    if (parse_options(argc, argv, &options, generated_run_id, sizeof(generated_run_id)) != 0) {
        usage(argv[0]);
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    OPENSSL_init_ssl(0, NULL);
    classical_context = create_context(&options.classical, options.ca_file);
    hybrid_context = create_context(&options.hybrid, options.ca_file);
    if (classical_context == NULL || hybrid_context == NULL) {
        fprintf(stderr, "unable to initialize TLS contexts; confirm this OpenSSL build supports X25519MLKEM768\n");
        SSL_CTX_free(classical_context);
        SSL_CTX_free(hybrid_context);
        return 1;
    }
    json_escape(OpenSSL_version(OPENSSL_VERSION), version_escaped, sizeof(version_escaped));
    snprintf(run_json, sizeof(run_json), "{\"run_id\":\"%s\",\"client_name\":\"openssl-c-client\",\"openssl_version\":\"%s\",\"iterations\":%d,\"warmup\":%d,\"notes\":\"Alternating classical/hybrid order; TLS 1.3; fresh full handshakes\"}", options.run_id, version_escaped, options.iterations, options.warmup);
    if (post_json(options.dashboard_host, options.dashboard_port, "/api/runs", run_json) != 0) {
        fprintf(stderr, "cannot create dashboard run; aborting so measurements are not lost\n");
        SSL_CTX_free(classical_context);
        SSL_CTX_free(hybrid_context);
        return 1;
    }
    printf("Run %s: %d warmups + %d measured connections per mode\n", options.run_id, options.warmup, options.iterations);
    printf("OpenSSL: %s\n", OpenSSL_version(OPENSSL_VERSION));
    for (index = 1; index <= options.warmup; index++) {
        probe(&options, &options.classical, classical_context, index, 0);
        probe(&options, &options.hybrid, hybrid_context, index, 0);
    }
    for (index = 1; index <= options.iterations; index++) {
        if (index % 2 == 1) {
            if (probe(&options, &options.classical, classical_context, index, 1) != 0) failures++;
            if (probe(&options, &options.hybrid, hybrid_context, index, 1) != 0) failures++;
        } else {
            if (probe(&options, &options.hybrid, hybrid_context, index, 1) != 0) failures++;
            if (probe(&options, &options.classical, classical_context, index, 1) != 0) failures++;
        }
    }
    snprintf(complete_path, sizeof(complete_path), "/api/runs/%s/complete", options.run_id);
    post_json(options.dashboard_host, options.dashboard_port, complete_path, "{}");
    printf("Completed %s with %d failed probes. Dashboard: http://localhost:8000/?run_id=%s\n", options.run_id, failures, options.run_id);
    SSL_CTX_free(classical_context);
    SSL_CTX_free(hybrid_context);
    return failures == 0 ? 0 : 1;
}
