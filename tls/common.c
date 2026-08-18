#define _POSIX_C_SOURCE 200809L

#include "common.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

uint64_t now_microseconds(void) {
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (uint64_t)value.tv_sec * 1000000ULL + (uint64_t)value.tv_nsec / 1000ULL;
}

int tcp_connect_host(const char *host, const char *port, char *error, size_t error_size) {
    struct addrinfo hints = {0};
    struct addrinfo *results = NULL;
    struct addrinfo *current = NULL;
    int socket_fd = -1;
    int status;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    status = getaddrinfo(host, port, &hints, &results);
    if (status != 0) {
        snprintf(error, error_size, "getaddrinfo: %s", gai_strerror(status));
        return -1;
    }
    for (current = results; current != NULL; current = current->ai_next) {
        socket_fd = socket(current->ai_family, current->ai_socktype, current->ai_protocol);
        if (socket_fd < 0) {
            continue;
        }
        if (connect(socket_fd, current->ai_addr, current->ai_addrlen) == 0) {
            int enabled = 1;
            setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
            break;
        }
        close(socket_fd);
        socket_fd = -1;
    }
    if (socket_fd < 0) {
        snprintf(error, error_size, "connect: %s", strerror(errno));
    }
    freeaddrinfo(results);
    return socket_fd;
}

static int send_all(int socket_fd, const char *data, size_t length) {
    size_t sent = 0;
    while (sent < length) {
        ssize_t result = send(socket_fd, data + sent, length - sent, 0);
        if (result <= 0) {
            return -1;
        }
        sent += (size_t)result;
    }
    return 0;
}

int post_json(const char *host, const char *port, const char *path, const char *json) {
    char error[256] = {0};
    char header[1024];
    char response[256] = {0};
    int socket_fd = tcp_connect_host(host, port, error, sizeof(error));
    int header_length;
    ssize_t received;

    if (socket_fd < 0) {
        fprintf(stderr, "dashboard connection failed: %s\n", error);
        return -1;
    }
    header_length = snprintf(
        header,
        sizeof(header),
        "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        path,
        host,
        strlen(json)
    );
    if (header_length <= 0 || (size_t)header_length >= sizeof(header) ||
        send_all(socket_fd, header, (size_t)header_length) != 0 ||
        send_all(socket_fd, json, strlen(json)) != 0) {
        fprintf(stderr, "dashboard request write failed\n");
        close(socket_fd);
        return -1;
    }
    received = recv(socket_fd, response, sizeof(response) - 1, 0);
    close(socket_fd);
    if (received <= 0) {
        fprintf(stderr, "dashboard returned no response\n");
        return -1;
    }
    response[received] = '\0';
    if (strstr(response, " 200 ") == NULL && strstr(response, " 201 ") == NULL) {
        fprintf(stderr, "dashboard rejected request: %.120s\n", response);
        return -1;
    }
    return 0;
}

void json_escape(const char *input, char *output, size_t output_size) {
    size_t source = 0;
    size_t target = 0;
    if (output_size == 0) {
        return;
    }
    while (input[source] != '\0' && target + 2 < output_size) {
        unsigned char character = (unsigned char)input[source++];
        if (character == '"' || character == '\\') {
            output[target++] = '\\';
            output[target++] = (char)character;
        } else if (character == '\n' || character == '\r' || character == '\t') {
            output[target++] = ' ';
        } else if (character >= 0x20) {
            output[target++] = (char)character;
        }
    }
    output[target] = '\0';
}

int valid_identifier(const char *value) {
    size_t index;
    size_t length = strlen(value);
    if (length == 0 || length > 160) {
        return 0;
    }
    for (index = 0; index < length; index++) {
        char character = value[index];
        if (!((character >= 'a' && character <= 'z') ||
              (character >= 'A' && character <= 'Z') ||
              (character >= '0' && character <= '9') ||
              character == '_' || character == '-' || character == '.')) {
            return 0;
        }
    }
    return 1;
}
