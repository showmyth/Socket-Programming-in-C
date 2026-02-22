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

#define DEFAULT_UDP_HOST "127.0.0.1"
#define DEFAULT_UDP_PORT "12345"
#define DEFAULT_UDP_MESSAGE "hello from udp_sender"

int main(int argc, char *argv[]) {
    const char *host = DEFAULT_UDP_HOST;
    const char *port = DEFAULT_UDP_PORT;
    const char *message = DEFAULT_UDP_MESSAGE;
    struct addrinfo hints;
    struct addrinfo *results = NULL;
    struct addrinfo *entry = NULL;
    int sock_fd = -1;
    int rc = EXIT_FAILURE;

    if (argc > 4) {
        fprintf(stderr, "Usage: %s [host] [port] [message]\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (argc >= 2) {
        host = argv[1];
    }
    if (argc >= 3) {
        port = argv[2];
    }
    if (argc >= 4) {
        message = argv[3];
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    if (getaddrinfo(host, port, &hints, &results) != 0) {
        log_error("getaddrinfo failed for %s:%s", host, port);
        return EXIT_FAILURE;
    }

    for (entry = results; entry != NULL; entry = entry->ai_next) {
        ssize_t sent = 0;
        char peer[128];

        sock_fd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (sock_fd < 0) {
            continue;
        }

        sent = sendto(sock_fd, message, strlen(message), 0, entry->ai_addr, entry->ai_addrlen);
        if (sent < 0) {
            log_error("sendto failed");
            close(sock_fd);
            sock_fd = -1;
            continue;
        }

        if (format_socket_address(entry->ai_addr, (socklen_t)entry->ai_addrlen, peer, sizeof(peer)) == 0) {
            log_info("sent %zd UDP bytes to %s", sent, peer);
        } else {
            log_info("sent %zd UDP bytes", sent);
        }
        rc = EXIT_SUCCESS;
        close(sock_fd);
        sock_fd = -1;
        break;
    }

    freeaddrinfo(results);
    if (rc != EXIT_SUCCESS) {
        log_error("unable to send UDP packet");
    }
    return rc;
}
