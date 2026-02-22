#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>

#define IO_BUFFER_SIZE 4096
#define LINE_BUFFER_SIZE 1024
#define FILE_NAME_SIZE 256
#define UPLOAD_DIR "uploads"

void log_info(const char *fmt, ...);
void log_error(const char *fmt, ...);

int set_nonblocking(int fd);
int wait_for_fd(int fd, bool for_write, int timeout_seconds);
ssize_t send_all(int fd, const void *buffer, size_t length);

int format_socket_address(const struct sockaddr *addr, socklen_t addr_len,
                          char *out, size_t out_len);
int sanitize_filename(const char *input, char *out, size_t out_len);
int create_directory_if_missing(const char *path);

#endif
