#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils.h"

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT "9090"
#define CLIENT_RX_BUFFER_SIZE 8192
#define MAX_FILE_BYTES (100ULL * 1024ULL * 1024ULL)

static void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s [host] [port]\n", program_name);
}

static void trim_newline(char *text) {
    size_t len = strlen(text);
    while (len > 0 && (text[len - 1] == '\n' || text[len - 1] == '\r')) {
        text[len - 1] = '\0';
        len--;
    }
}

static void discard_stdin_until_newline(void) {
    int ch = 0;
    do {
        ch = getchar();
    } while (ch != '\n' && ch != EOF);
}

static const char *path_basename(const char *path) {
    const char *last_slash = strrchr(path, '/');
    const char *last_backslash = strrchr(path, '\\');
    const char *candidate = path;

    if (last_slash != NULL && last_slash + 1 > candidate) {
        candidate = last_slash + 1;
    }
    if (last_backslash != NULL && last_backslash + 1 > candidate) {
        candidate = last_backslash + 1;
    }
    return candidate;
}

static int connect_to_server(const char *host, const char *port, char *peer, size_t peer_len) {
    struct addrinfo hints;
    struct addrinfo *results = NULL;
    struct addrinfo *entry = NULL;
    int sock_fd = -1;
    int rc = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    rc = getaddrinfo(host, port, &hints, &results);
    if (rc != 0) {
        log_error("getaddrinfo failed for %s:%s (%s)", host, port, gai_strerror(rc));
        return -1;
    }

    for (entry = results; entry != NULL; entry = entry->ai_next) {
        int so_error = 0;
        socklen_t so_error_len = sizeof(so_error);

        sock_fd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (sock_fd < 0) {
            continue;
        }
        if (set_nonblocking(sock_fd) < 0) {
            log_error("failed to set client socket non-blocking");
            close(sock_fd);
            sock_fd = -1;
            continue;
        }

        rc = connect(sock_fd, entry->ai_addr, entry->ai_addrlen);
        if (rc < 0) {
            if (errno != EINPROGRESS) {
                close(sock_fd);
                sock_fd = -1;
                continue;
            }
            rc = wait_for_fd(sock_fd, true, 10);
            if (rc <= 0) {
                if (rc == 0) {
                    errno = ETIMEDOUT;
                }
                log_error("connection attempt timed out");
                close(sock_fd);
                sock_fd = -1;
                continue;
            }
            if (getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) < 0) {
                log_error("getsockopt(SO_ERROR) failed");
                close(sock_fd);
                sock_fd = -1;
                continue;
            }
            if (so_error != 0) {
                errno = so_error;
                close(sock_fd);
                sock_fd = -1;
                continue;
            }
        }

        if (format_socket_address(entry->ai_addr, (socklen_t)entry->ai_addrlen, peer, peer_len) < 0) {
            (void)snprintf(peer, peer_len, "%s:%s", host, port);
        }
        break;
    }

    freeaddrinfo(results);
    return sock_fd;
}

static int send_chat_line(int sock_fd, const char *line) {
    size_t line_len = strlen(line);
    char wire_line[LINE_BUFFER_SIZE + 2];

    if (line_len == 0) {
        return 0;
    }
    if (line_len > LINE_BUFFER_SIZE) {
        log_error("message is too long (max %d chars)", LINE_BUFFER_SIZE);
        return -1;
    }
    if (snprintf(wire_line, sizeof(wire_line), "%s\n", line) < 0) {
        log_error("failed to format outgoing message");
        return -1;
    }
    if (send_all(sock_fd, wire_line, strlen(wire_line)) < 0) {
        log_error("send failed");
        return -1;
    }
    return 0;
}

static int send_file(int sock_fd, const char *path) {
    int file_fd = -1;
    struct stat st;
    ssize_t bytes_read = 0;
    uint64_t file_size = 0;
    uint64_t sent_size = 0;
    char file_name[FILE_NAME_SIZE];
    char safe_name[FILE_NAME_SIZE];
    char header[LINE_BUFFER_SIZE];
    char chunk[IO_BUFFER_SIZE];

    if (path == NULL || *path == '\0') {
        log_error("usage: /send <file_path>");
        return -1;
    }

    file_fd = open(path, O_RDONLY);
    if (file_fd < 0) {
        log_error("failed to open file '%s'", path);
        return -1;
    }
    if (fstat(file_fd, &st) < 0) {
        log_error("fstat failed for '%s'", path);
        close(file_fd);
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        log_error("'%s' is not a regular file", path);
        close(file_fd);
        return -1;
    }
    if (st.st_size < 0) {
        log_error("invalid file size for '%s'", path);
        close(file_fd);
        return -1;
    }

    file_size = (uint64_t)st.st_size;
    if (file_size == 0) {
        log_error("refusing to send empty file '%s'", path);
        close(file_fd);
        return -1;
    }
    if (file_size > MAX_FILE_BYTES) {
        log_error("file '%s' exceeds %llu-byte limit", path, (unsigned long long)MAX_FILE_BYTES);
        close(file_fd);
        return -1;
    }

    (void)snprintf(file_name, sizeof(file_name), "%s", path_basename(path));
    if (sanitize_filename(file_name, safe_name, sizeof(safe_name)) < 0) {
        log_error("invalid file name '%s'", file_name);
        close(file_fd);
        return -1;
    }

    if (snprintf(header, sizeof(header), "FILE_BEGIN %s %" PRIu64 "\n", safe_name, file_size) < 0) {
        log_error("failed to format file header");
        close(file_fd);
        return -1;
    }

    /* TCP is a byte stream, so we send a text header first, then raw file bytes. */
    if (send_all(sock_fd, header, strlen(header)) < 0) {
        log_error("failed to send file header for '%s'", safe_name);
        close(file_fd);
        return -1;
    }

    for (;;) {
        bytes_read = read(file_fd, chunk, sizeof(chunk));
        if (bytes_read > 0) {
            if (send_all(sock_fd, chunk, (size_t)bytes_read) < 0) {
                log_error("failed to send file data for '%s'", safe_name);
                close(file_fd);
                return -1;
            }
            sent_size += (uint64_t)bytes_read;
            continue;
        }
        if (bytes_read == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        log_error("read failed while sending '%s'", safe_name);
        close(file_fd);
        return -1;
    }

    close(file_fd);
    log_info("sent file '%s' (%" PRIu64 " bytes)", safe_name, sent_size);
    return 0;
}

static int process_server_messages(char *rx_buf, size_t *rx_len) {
    size_t len = *rx_len;

    for (;;) {
        char *newline = memchr(rx_buf, '\n', len);
        size_t line_len = 0;
        size_t consumed = 0;

        if (newline == NULL) {
            if (len == CLIENT_RX_BUFFER_SIZE) {
                log_error("incoming message exceeded %d bytes", CLIENT_RX_BUFFER_SIZE);
                return -1;
            }
            break;
        }

        line_len = (size_t)(newline - rx_buf);
        if (line_len > 0 && rx_buf[line_len - 1] == '\r') {
            line_len--;
        }

        if (line_len > 0) {
            if (fwrite(rx_buf, 1, line_len, stdout) != line_len) {
                log_error("stdout write failed");
                return -1;
            }
        }
        if (fputc('\n', stdout) == EOF) {
            log_error("stdout write failed");
            return -1;
        }
        if (fflush(stdout) == EOF) {
            log_error("stdout flush failed");
            return -1;
        }

        consumed = (size_t)(newline - rx_buf) + 1;
        memmove(rx_buf, rx_buf + consumed, len - consumed);
        len -= consumed;
    }

    *rx_len = len;
    return 0;
}

static int handle_socket_readable(int sock_fd, char *rx_buf, size_t *rx_len) {
    for (;;) {
        char chunk[IO_BUFFER_SIZE];
        ssize_t received = recv(sock_fd, chunk, sizeof(chunk), 0);

        if (received > 0) {
            if ((size_t)received > CLIENT_RX_BUFFER_SIZE - *rx_len) {
                log_error("receive buffer overflow prevented");
                return -1;
            }
            memcpy(rx_buf + *rx_len, chunk, (size_t)received);
            *rx_len += (size_t)received;
            if (process_server_messages(rx_buf, rx_len) < 0) {
                return -1;
            }
            continue;
        }

        if (received == 0) {
            log_info("server closed the connection");
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 1;
        }
        log_error("recv failed");
        return -1;
    }
}

static int handle_user_input(int sock_fd) {
    char input[LINE_BUFFER_SIZE + 1];

    if (fgets(input, sizeof(input), stdin) == NULL) {
        return 0;
    }
    if (strchr(input, '\n') == NULL && !feof(stdin)) {
        discard_stdin_until_newline();
        errno = 0;
        log_error("input line too long (max %d characters)", LINE_BUFFER_SIZE);
        return 1;
    }

    trim_newline(input);
    if (input[0] == '\0') {
        return 1;
    }
    if (strcmp(input, "/quit") == 0) {
        return 0;
    }
    if (strcmp(input, "/help") == 0) {
        printf("Commands:\n");
        printf("  /send <path>  Upload file to server\n");
        printf("  /quit         Disconnect\n");
        printf("  /help         Show this help\n");
        return 1;
    }
    if (strncmp(input, "/send ", 6) == 0) {
        const char *path = input + 6;
        while (*path == ' ') {
            path++;
        }
        if (send_file(sock_fd, path) < 0) {
            return -1;
        }
        return 1;
    }
    if (send_chat_line(sock_fd, input) < 0) {
        return -1;
    }
    return 1;
}

int main(int argc, char *argv[]) {
    const char *host = DEFAULT_HOST;
    const char *port = DEFAULT_PORT;
    int sock_fd = -1;
    int should_run = 1;
    char peer[128];
    char rx_buf[CLIENT_RX_BUFFER_SIZE];
    size_t rx_len = 0;

    memset(peer, 0, sizeof(peer));
    memset(rx_buf, 0, sizeof(rx_buf));

    if (argc > 3) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (argc >= 2) {
        host = argv[1];
    }
    if (argc == 3) {
        port = argv[2];
    }

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        log_error("failed to ignore SIGPIPE");
        return EXIT_FAILURE;
    }

    sock_fd = connect_to_server(host, port, peer, sizeof(peer));
    if (sock_fd < 0) {
        log_error("unable to connect to %s:%s", host, port);
        return EXIT_FAILURE;
    }

    log_info("connected to %s", peer);
    printf("Type chat messages and press Enter.\n");
    printf("Use /send <path> to upload a file, /quit to exit.\n");

    while (should_run) {
        fd_set read_fds;
        int max_fd = sock_fd;
        int ready = 0;
        int input_status = 0;
        int socket_status = 0;

        /* One event loop handles local input and server messages without threads. */
        FD_ZERO(&read_fds);
        FD_SET(sock_fd, &read_fds);
        FD_SET(STDIN_FILENO, &read_fds);

        ready = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_error("select failed");
            break;
        }

        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            input_status = handle_user_input(sock_fd);
            if (input_status <= 0) {
                if (input_status < 0) {
                    log_error("failed to process local input");
                }
                should_run = 0;
            }
        }
        if (!should_run) {
            break;
        }

        if (FD_ISSET(sock_fd, &read_fds)) {
            socket_status = handle_socket_readable(sock_fd, rx_buf, &rx_len);
            if (socket_status <= 0) {
                should_run = 0;
            }
        }
    }

    if (close(sock_fd) < 0) {
        log_error("close failed on client socket");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
 
