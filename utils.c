#define _POSIX_C_SOURCE 200809L

#include "utils.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static void v_log(FILE *stream, const char *level, const char *fmt, va_list args) {
    char time_buf[32];
    struct timespec ts;
    struct tm tm_value;

    memset(time_buf, 0, sizeof(time_buf));
    if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
        ts.tv_sec = 0;
    }
    if (localtime_r(&ts.tv_sec, &tm_value) == NULL) {
        memset(&tm_value, 0, sizeof(tm_value));
    }
    if (strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_value) == 0) {
        (void)snprintf(time_buf, sizeof(time_buf), "0000-00-00 00:00:00");
    }

    fprintf(stream, "[%s] [%s] ", time_buf, level);
    vfprintf(stream, fmt, args);
    fputc('\n', stream);
    fflush(stream);
}

void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    v_log(stdout, "INFO", fmt, args);
    va_end(args);
}

void log_error(const char *fmt, ...) {
    int saved_errno = errno;
    va_list args;

    va_start(args, fmt);
    v_log(stderr, "ERROR", fmt, args);
    va_end(args);

    if (saved_errno != 0) {
        fprintf(stderr, "[errno=%d] %s\n", saved_errno, strerror(saved_errno));
        fflush(stderr);
    }
}

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }
    return 0;
}

int wait_for_fd(int fd, bool for_write, int timeout_seconds) {
    int rc = 0;

    for (;;) {
        fd_set fdset;
        struct timeval timeout;
        struct timeval *timeout_ptr = NULL;

        FD_ZERO(&fdset);
        FD_SET(fd, &fdset);

        if (timeout_seconds >= 0) {
            timeout.tv_sec = timeout_seconds;
            timeout.tv_usec = 0;
            timeout_ptr = &timeout;
        }

        if (for_write) {
            rc = select(fd + 1, NULL, &fdset, NULL, timeout_ptr);
        } else {
            rc = select(fd + 1, &fdset, NULL, NULL, timeout_ptr);
        }

        if (rc < 0 && errno == EINTR) {
            continue;
        }
        return rc;
    }
}

ssize_t send_all(int fd, const void *buffer, size_t length) {
    const unsigned char *cursor = (const unsigned char *)buffer;
    size_t sent_total = 0;

    while (sent_total < length) {
        ssize_t sent_now = 0;
#ifdef MSG_NOSIGNAL
        sent_now = send(fd, cursor + sent_total, length - sent_total, MSG_NOSIGNAL);
#else
        sent_now = send(fd, cursor + sent_total, length - sent_total, 0);
#endif
        if (sent_now > 0) {
            sent_total += (size_t)sent_now;
            continue;
        }
        if (sent_now == 0) {
            errno = ECONNRESET;
            return -1;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            int wait_rc = wait_for_fd(fd, true, 10);
            if (wait_rc > 0) {
                continue;
            }
            if (wait_rc == 0) {
                errno = ETIMEDOUT;
            }
            return -1;
        }
        return -1;
    }

    return (ssize_t)sent_total;
}

int format_socket_address(const struct sockaddr *addr, socklen_t addr_len, char *out, size_t out_len) {
    /* NI_MAXHOST/NI_MAXSERV are not consistently exposed across libc feature sets. */
    char host[128];
    char service[32];
    int rc = 0;

    if (addr == NULL || out == NULL || out_len == 0) {
        errno = EINVAL;
        return -1;
    }

    rc = getnameinfo(addr, addr_len, host, sizeof(host), service, sizeof(service),
                     NI_NUMERICHOST | NI_NUMERICSERV);
    if (rc != 0) {
        errno = EINVAL;
        return -1;
    }

    if (addr->sa_family == AF_INET6) {
        if (snprintf(out, out_len, "[%s]:%s", host, service) < 0) {
            return -1;
        }
    } else {
        if (snprintf(out, out_len, "%s:%s", host, service) < 0) {
            return -1;
        }
    }

    return 0;
}

int sanitize_filename(const char *input, char *out, size_t out_len) {
    const char *name = input;
    const char *last_slash = NULL;
    const char *last_backslash = NULL;
    size_t out_index = 0;

    if (input == NULL || out == NULL || out_len == 0) {
        errno = EINVAL;
        return -1;
    }

    last_slash = strrchr(input, '/');
    last_backslash = strrchr(input, '\\');
    if (last_slash != NULL && last_slash + 1 > name) {
        name = last_slash + 1;
    }
    if (last_backslash != NULL && last_backslash + 1 > name) {
        name = last_backslash + 1;
    }

    if (*name == '\0') {
        errno = EINVAL;
        return -1;
    }

    while (*name != '\0') {
        unsigned char ch = (unsigned char)*name;
        if (out_index + 1 >= out_len) {
            errno = ENAMETOOLONG;
            return -1;
        }
        if (isalnum(ch) || ch == '.' || ch == '-' || ch == '_') {
            out[out_index++] = (char)ch;
        } else {
            out[out_index++] = '_';
        }
        name++;
    }

    out[out_index] = '\0';
    if (strcmp(out, ".") == 0 || strcmp(out, "..") == 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int create_directory_if_missing(const char *path) {
    struct stat st;

    if (path == NULL || *path == '\0') {
        errno = EINVAL;
        return -1;
    }

    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0;
        }
        errno = ENOTDIR;
        return -1;
    }
    if (errno != ENOENT) {
        return -1;
    }
    if (mkdir(path, 0755) < 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}
