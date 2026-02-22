#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils.h"

#define DEFAULT_UDP_PORT "12345"

int main(int argc, char *argv[]) {
    const char *port = DEFAULT_UDP_PORT;
    struct addrinfo hints;
    struct addrinfo *results = NULL;
    struct addrinfo *entry = NULL;
    int sock_fd = -1;
    int rc = EXIT_FAILURE;

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [port]\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (argc == 2) {
        port = argv[1];
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(NULL, port, &hints, &results) != 0) {
        log_error("getaddrinfo failed for UDP port %s", port);
        return EXIT_FAILURE;
    }

    for (entry = results; entry != NULL; entry = entry->ai_next) {
        sock_fd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (sock_fd < 0) {
            continue;
        }
        if (bind(sock_fd, entry->ai_addr, entry->ai_addrlen) == 0) {
            rc = EXIT_SUCCESS;
            break;
        }
        close(sock_fd);
        sock_fd = -1;
    }

    freeaddrinfo(results);
    if (rc != EXIT_SUCCESS || sock_fd < 0) {
        log_error("unable to bind UDP receiver on port %s", port);
        return EXIT_FAILURE;
    }

    log_info("UDP receiver listening on port %s", port);
    for (;;) {
        char buffer[IO_BUFFER_SIZE];
        struct sockaddr_storage peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        ssize_t received = recvfrom(sock_fd, buffer, sizeof(buffer) - 1, 0,
                                    (struct sockaddr *)&peer_addr, &peer_len);
        char peer[128];

        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_error("recvfrom failed");
            break;
        }

        buffer[received] = '\0';
        if (format_socket_address((const struct sockaddr *)&peer_addr, peer_len, peer, sizeof(peer)) < 0) {
            (void)snprintf(peer, sizeof(peer), "unknown");
        }
        log_info("UDP packet from %s: %s", peer, buffer);
    }

    if (close(sock_fd) < 0) {
        log_error("failed to close UDP socket");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
