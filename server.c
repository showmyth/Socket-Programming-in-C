#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
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

#define DEFAULT_PORT "9090"
#define LISTEN_BACKLOG 16
#define CLIENT_RX_BUFFER_SIZE 8192
#define SERVER_MESSAGE_SIZE 2048
#define MAX_FILE_BYTES (100ULL * 1024ULL * 1024ULL)

enum client_mode {
    CLIENT_MODE_CHAT = 0,
    CLIENT_MODE_RECEIVING_FILE = 1
};

struct file_state {
    enum client_mode mode;
    int fd;
    uint64_t total_bytes;
    uint64_t remaining_bytes;
    char name[FILE_NAME_SIZE];
    char path[512];
};

struct client {
    int fd;
    char address[128];
    char rx_buf[CLIENT_RX_BUFFER_SIZE];
    size_t rx_len;
    struct file_state file;
};

struct server_state {
    int listen_fd;
    struct client clients[FD_SETSIZE];
};

static void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s [port]\n", program_name);
}

static void reset_file_state(struct file_state *file_state) {
    if (file_state == NULL) {
        return;
    }
    file_state->mode = CLIENT_MODE_CHAT;
    file_state->fd = -1;
    file_state->total_bytes = 0;
    file_state->remaining_bytes = 0;
    memset(file_state->name, 0, sizeof(file_state->name));
    memset(file_state->path, 0, sizeof(file_state->path));
}

static void init_server_state(struct server_state *state) {
    int fd = 0;

    state->listen_fd = -1;
    for (fd = 0; fd < FD_SETSIZE; fd++) {
        state->clients[fd].fd = -1;
        state->clients[fd].rx_len = 0;
        memset(state->clients[fd].address, 0, sizeof(state->clients[fd].address));
        memset(state->clients[fd].rx_buf, 0, sizeof(state->clients[fd].rx_buf));
        reset_file_state(&state->clients[fd].file);
    }
}

static void shift_client_buffer(struct client *client, size_t consumed) {
    if (consumed >= client->rx_len) {
        client->rx_len = 0;
        return;
    }
    memmove(client->rx_buf, client->rx_buf + consumed, client->rx_len - consumed);
    client->rx_len -= consumed;
}

static void broadcast_message(struct server_state *state, const char *message, int exclude_fd);

static void drop_client(struct server_state *state, int fd, const char *reason, bool notify_peers) {
    struct client *client = NULL;
    char address[128];
    char notification[SERVER_MESSAGE_SIZE];
    bool had_partial_file = false;
    char partial_path[512];

    if (fd < 0 || fd >= FD_SETSIZE) {
        return;
    }

    client = &state->clients[fd];
    if (client->fd < 0) {
        return;
    }

    (void)snprintf(address, sizeof(address), "%s", client->address);
    memset(partial_path, 0, sizeof(partial_path));
    if (client->file.mode == CLIENT_MODE_RECEIVING_FILE && client->file.fd >= 0 &&
        client->file.remaining_bytes > 0 && client->file.path[0] != '\0') {
        had_partial_file = true;
        (void)snprintf(partial_path, sizeof(partial_path), "%s", client->file.path);
    }

    if (client->file.fd >= 0) {
        if (close(client->file.fd) < 0) {
            log_error("failed to close file descriptor for %s", address);
        }
    }
    if (had_partial_file) {
        if (unlink(partial_path) < 0) {
            log_error("failed to remove partial upload '%s'", partial_path);
        } else {
            log_info("removed partial upload '%s'", partial_path);
        }
    }

    if (close(client->fd) < 0) {
        log_error("failed to close client socket %s", address);
    }

    client->fd = -1;
    client->rx_len = 0;
    memset(client->address, 0, sizeof(client->address));
    memset(client->rx_buf, 0, sizeof(client->rx_buf));
    reset_file_state(&client->file);

    log_info("client disconnected: %s (%s)", address, reason);

    if (notify_peers) {
        if (snprintf(notification, sizeof(notification), "[server] %s disconnected (%s)\n", address, reason) < 0) {
            return;
        }
        broadcast_message(state, notification, -1);
    }
}

static int send_to_client(struct server_state *state, int fd, const char *message) {
    (void)state;
    if (send_all(fd, message, strlen(message)) < 0) {
        log_error("send failed to fd=%d", fd);
        return -1;
    }
    return 0;
}

static void broadcast_message(struct server_state *state, const char *message, int exclude_fd) {
    int fd = 0;

    for (fd = 0; fd < FD_SETSIZE; fd++) {
        if (state->clients[fd].fd < 0 || fd == exclude_fd) {
            continue;
        }
        if (send_to_client(state, fd, message) < 0) {
            /* Avoid mutating client table during active per-client processing. */
            continue;
        }
    }
}

static int begin_file_receive(struct server_state *state, struct client *client, const char *line) {
    const char *prefix = "FILE_BEGIN ";
    const char *payload = line + strlen(prefix);
    const char *last_space = NULL;
    uint64_t expected_bytes = 0;
    char raw_file_name[FILE_NAME_SIZE];
    char clean_file_name[FILE_NAME_SIZE];
    char path[512];
    char notice[SERVER_MESSAGE_SIZE];
    char ack[SERVER_MESSAGE_SIZE];
    size_t name_len = 0;
    char *size_end = NULL;
    int file_fd = -1;

    while (*payload == ' ') {
        payload++;
    }
    if (*payload == '\0') {
        return -1;
    }

    last_space = strrchr(payload, ' ');
    if (last_space == NULL || last_space == payload) {
        return -1;
    }

    name_len = (size_t)(last_space - payload);
    if (name_len == 0 || name_len >= sizeof(raw_file_name)) {
        return -1;
    }

    memcpy(raw_file_name, payload, name_len);
    raw_file_name[name_len] = '\0';

    errno = 0;
    expected_bytes = strtoull(last_space + 1, &size_end, 10);
    if (errno != 0 || size_end == last_space + 1 || *size_end != '\0') {
        return -1;
    }
    if (expected_bytes == 0 || expected_bytes > MAX_FILE_BYTES) {
        return -1;
    }
    if (sanitize_filename(raw_file_name, clean_file_name, sizeof(clean_file_name)) < 0) {
        return -1;
    }
    if (create_directory_if_missing(UPLOAD_DIR) < 0) {
        log_error("failed to create upload directory '%s'", UPLOAD_DIR);
        return -1;
    }

    if (snprintf(path, sizeof(path), "%s/client%d_%s", UPLOAD_DIR, client->fd, clean_file_name) < 0) {
        return -1;
    }

    file_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (file_fd < 0) {
        log_error("failed to open upload destination '%s'", path);
        return -1;
    }

    client->file.mode = CLIENT_MODE_RECEIVING_FILE;
    client->file.fd = file_fd;
    client->file.total_bytes = expected_bytes;
    client->file.remaining_bytes = expected_bytes;
    (void)snprintf(client->file.name, sizeof(client->file.name), "%s", clean_file_name);
    (void)snprintf(client->file.path, sizeof(client->file.path), "%s", path);

    if (snprintf(ack, sizeof(ack), "[server] receiving file '%s' (%" PRIu64 " bytes)\n",
                 clean_file_name, expected_bytes) >= 0) {
        if (send_to_client(state, client->fd, ack) < 0) {
            return -1;
        }
    }

    if (snprintf(notice, sizeof(notice), "[server] %s started uploading '%s' (%" PRIu64 " bytes)\n",
                 client->address, clean_file_name, expected_bytes) >= 0) {
        broadcast_message(state, notice, client->fd);
    }
    log_info("file upload started by %s: %s (%" PRIu64 " bytes)",
             client->address, client->file.path, expected_bytes);
    return 0;
}

static int handle_chat_line(struct server_state *state, struct client *client, const char *line) {
    char out[SERVER_MESSAGE_SIZE];

    if (line[0] == '\0') {
        return 0;
    }
    if (strcmp(line, "/quit") == 0) {
        return 1;
    }
    if (strncmp(line, "FILE_BEGIN ", 11) == 0) {
        if (begin_file_receive(state, client, line) < 0) {
            if (send_to_client(state, client->fd,
                               "[server] invalid file header. Use: FILE_BEGIN <name> <size>\n") < 0) {
                return -1;
            }
            return 0;
        }
        return 0;
    }

    if (snprintf(out, sizeof(out), "[%s] %s\n", client->address, line) < 0) {
        log_error("failed to format chat message");
        return -1;
    }
    broadcast_message(state, out, -1);
    return 0;
}

static int process_client_buffer(struct server_state *state, struct client *client) {
    for (;;) {
        if (client->file.mode == CLIENT_MODE_RECEIVING_FILE) {
            ssize_t wrote = 0;
            size_t to_write = 0;
            char completed[SERVER_MESSAGE_SIZE];

            if (client->rx_len == 0) {
                return 0;
            }

            /* In file mode, every byte belongs to the file payload until remaining_bytes reaches 0. */
            to_write = client->rx_len;
            if ((uint64_t)to_write > client->file.remaining_bytes) {
                to_write = (size_t)client->file.remaining_bytes;
            }

            wrote = write(client->file.fd, client->rx_buf, to_write);
            if (wrote < 0) {
                if (errno == EINTR) {
                    continue;
                }
                log_error("write failed for upload '%s'", client->file.path);
                return -1;
            }
            if (wrote == 0) {
                errno = EIO;
                log_error("zero-byte write for upload '%s'", client->file.path);
                return -1;
            }

            shift_client_buffer(client, (size_t)wrote);
            client->file.remaining_bytes -= (uint64_t)wrote;

            if (client->file.remaining_bytes == 0) {
                if (close(client->file.fd) < 0) {
                    log_error("failed to close upload '%s'", client->file.path);
                    return -1;
                }
                client->file.fd = -1;

                if (snprintf(completed, sizeof(completed),
                             "[server] file '%s' uploaded (%" PRIu64 " bytes)\n",
                             client->file.name, client->file.total_bytes) >= 0) {
                    broadcast_message(state, completed, -1);
                }

                log_info("file upload completed from %s: %s (%" PRIu64 " bytes)",
                         client->address, client->file.path, client->file.total_bytes);
                reset_file_state(&client->file);
                continue;
            }

            if (client->rx_len == 0) {
                return 0;
            }
            continue;
        }

        {
            char *newline = memchr(client->rx_buf, '\n', client->rx_len);
            size_t raw_len = 0;
            size_t line_len = 0;
            size_t consumed = 0;
            char line[LINE_BUFFER_SIZE];
            int rc = 0;

            if (newline == NULL) {
                if (client->rx_len >= sizeof(client->rx_buf)) {
                    if (send_to_client(state, client->fd,
                                       "[server] message too long; disconnecting\n") < 0) {
                        return -1;
                    }
                    return -1;
                }
                return 0;
            }

            raw_len = (size_t)(newline - client->rx_buf);
            line_len = raw_len;
            if (line_len > 0 && client->rx_buf[line_len - 1] == '\r') {
                line_len--;
            }
            if (line_len >= sizeof(line)) {
                if (send_to_client(state, client->fd,
                                   "[server] line exceeded server limits\n") < 0) {
                    return -1;
                }
                return -1;
            }

            memcpy(line, client->rx_buf, line_len);
            line[line_len] = '\0';

            consumed = raw_len + 1;
            shift_client_buffer(client, consumed);

            rc = handle_chat_line(state, client, line);
            if (rc != 0) {
                return rc;
            }
        }
    }
}

static int read_client_data(struct server_state *state, struct client *client) {
    for (;;) {
        char temp[IO_BUFFER_SIZE];
        ssize_t bytes_read = recv(client->fd, temp, sizeof(temp), 0);

        if (bytes_read > 0) {
            if ((size_t)bytes_read > sizeof(client->rx_buf) - client->rx_len) {
                log_error("input buffer overflow prevented for %s", client->address);
                return -1;
            }
            memcpy(client->rx_buf + client->rx_len, temp, (size_t)bytes_read);
            client->rx_len += (size_t)bytes_read;

            {
                int process_rc = process_client_buffer(state, client);
                if (process_rc != 0) {
                    return process_rc;
                }
            }
            continue;
        }

        if (bytes_read == 0) {
            return 1;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        log_error("recv failed for %s", client->address);
        return -1;
    }
}

static int accept_pending_clients(struct server_state *state) {
    for (;;) {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        int client_fd = accept(state->listen_fd, (struct sockaddr *)&addr, &addr_len);
        char address[128];
        char notice[SERVER_MESSAGE_SIZE];

        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            log_error("accept failed");
            return -1;
        }

        if (client_fd >= FD_SETSIZE) {
            log_error("rejecting client fd=%d: exceeds FD_SETSIZE=%d", client_fd, FD_SETSIZE);
            if (close(client_fd) < 0) {
                log_error("close failed while rejecting oversized fd");
            }
            continue;
        }
        if (set_nonblocking(client_fd) < 0) {
            log_error("failed to set non-blocking mode on client fd=%d", client_fd);
            if (close(client_fd) < 0) {
                log_error("close failed for client fd=%d", client_fd);
            }
            continue;
        }
        if (format_socket_address((const struct sockaddr *)&addr, addr_len, address, sizeof(address)) < 0) {
            (void)snprintf(address, sizeof(address), "unknown");
        }

        memset(&state->clients[client_fd], 0, sizeof(state->clients[client_fd]));
        state->clients[client_fd].fd = client_fd;
        (void)snprintf(state->clients[client_fd].address, sizeof(state->clients[client_fd].address), "%s", address);
        reset_file_state(&state->clients[client_fd].file);

        log_info("client connected: %s (fd=%d)", state->clients[client_fd].address, client_fd);

        if (snprintf(notice, sizeof(notice), "[server] %s joined the chat\n",
                     state->clients[client_fd].address) >= 0) {
            broadcast_message(state, notice, -1);
        }
        if (send_to_client(state, client_fd,
                           "[server] welcome. Commands: normal text chat, /quit, /send <path> (from client)\n") < 0) {
            drop_client(state, client_fd, "send failure", false);
            continue;
        }
    }
}

static int setup_listening_socket(const char *port) {
    struct addrinfo hints;
    struct addrinfo *results = NULL;
    struct addrinfo *entry = NULL;
    int listen_fd = -1;
    int rc = 0;
    int yes = 1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    rc = getaddrinfo(NULL, port, &hints, &results);
    if (rc != 0) {
        log_error("getaddrinfo failed on port %s (%s)", port, gai_strerror(rc));
        return -1;
    }

    for (entry = results; entry != NULL; entry = entry->ai_next) {
        listen_fd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (listen_fd < 0) {
            continue;
        }

        if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
            log_error("setsockopt(SO_REUSEADDR) failed");
            close(listen_fd);
            listen_fd = -1;
            continue;
        }

#ifdef IPV6_V6ONLY
        if (entry->ai_family == AF_INET6) {
            int no = 0;
            if (setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no)) < 0) {
                log_error("setsockopt(IPV6_V6ONLY=0) failed");
                close(listen_fd);
                listen_fd = -1;
                continue;
            }
        }
#endif

        if (bind(listen_fd, entry->ai_addr, entry->ai_addrlen) < 0) {
            close(listen_fd);
            listen_fd = -1;
            continue;
        }
        if (listen(listen_fd, LISTEN_BACKLOG) < 0) {
            log_error("listen failed");
            close(listen_fd);
            listen_fd = -1;
            continue;
        }
        if (set_nonblocking(listen_fd) < 0) {
            log_error("failed to set non-blocking mode on listening socket");
            close(listen_fd);
            listen_fd = -1;
            continue;
        }
        break;
    }

    freeaddrinfo(results);

    if (listen_fd >= 0) {
        struct sockaddr_storage local_addr;
        socklen_t local_len = sizeof(local_addr);
        char bound[128];

        if (getsockname(listen_fd, (struct sockaddr *)&local_addr, &local_len) == 0 &&
            format_socket_address((const struct sockaddr *)&local_addr, local_len, bound, sizeof(bound)) == 0) {
            log_info("listening on %s (non-blocking, select-based)", bound);
        } else {
            log_info("listening on port %s (non-blocking, select-based)", port);
        }
    }

    return listen_fd;
}

static int run_event_loop(struct server_state *state) {
    for (;;) {
        fd_set read_fds;
        int max_fd = state->listen_fd;
        int ready = 0;
        int fd = 0;

        /* select() lets one thread monitor all client sockets plus the listening socket. */
        FD_ZERO(&read_fds);
        FD_SET(state->listen_fd, &read_fds);

        for (fd = 0; fd < FD_SETSIZE; fd++) {
            if (state->clients[fd].fd < 0) {
                continue;
            }
            FD_SET(fd, &read_fds);
            if (fd > max_fd) {
                max_fd = fd;
            }
        }

        ready = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            log_error("select failed in main loop");
            return -1;
        }

        if (FD_ISSET(state->listen_fd, &read_fds)) {
            if (accept_pending_clients(state) < 0) {
                return -1;
            }
        }

        for (fd = 0; fd < FD_SETSIZE; fd++) {
            int rc = 0;

            if (state->clients[fd].fd < 0) {
                continue;
            }
            if (!FD_ISSET(fd, &read_fds)) {
                continue;
            }

            rc = read_client_data(state, &state->clients[fd]);
            if (rc == 0) {
                continue;
            }
            if (rc > 0) {
                drop_client(state, fd, "peer closed connection", true);
            } else {
                drop_client(state, fd, "read/write error", true);
            }
        }
    }
}

static void shutdown_server(struct server_state *state) {
    int fd = 0;

    for (fd = 0; fd < FD_SETSIZE; fd++) {
        if (state->clients[fd].fd >= 0) {
            drop_client(state, fd, "server shutdown", false);
        }
    }
    if (state->listen_fd >= 0) {
        if (close(state->listen_fd) < 0) {
            log_error("failed to close listening socket");
        }
        state->listen_fd = -1;
    }
}

int main(int argc, char *argv[]) {
    const char *port = DEFAULT_PORT;
    struct server_state *state = NULL;
    int rc = EXIT_SUCCESS;

    if (argc > 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (argc == 2) {
        port = argv[1];
    }

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        log_error("failed to ignore SIGPIPE");
        return EXIT_FAILURE;
    }
    if (create_directory_if_missing(UPLOAD_DIR) < 0) {
        log_error("failed to prepare upload directory '%s'", UPLOAD_DIR);
        return EXIT_FAILURE;
    }

    state = (struct server_state *)calloc(1, sizeof(*state));
    if (state == NULL) {
        log_error("failed to allocate server state");
        return EXIT_FAILURE;
    }

    init_server_state(state);
    state->listen_fd = setup_listening_socket(port);
    if (state->listen_fd < 0) {
        free(state);
        return EXIT_FAILURE;
    }

    log_info("server started. Press Ctrl+C to stop.");
    if (run_event_loop(state) < 0) {
        rc = EXIT_FAILURE;
    }

    shutdown_server(state);
    free(state);
    return rc;
}
