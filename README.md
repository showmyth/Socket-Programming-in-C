# Socket-Programming-in-C

Educational networking project in C (POSIX/Linux) with:
- TCP chat server (`select()`-based, non-blocking, IPv4/IPv6)
- TCP client (interactive chat + file upload)
- UDP sender/receiver examples

The code is intentionally small enough to study, but includes production-style error handling and safer input processing.

## Project Overview

This repository demonstrates common systems-programming networking patterns:
- Socket lifecycle: `socket() -> bind() -> listen() -> accept()`
- Concurrent multi-client handling with `select()` (no threads)
- Non-blocking sockets with `fcntl(O_NONBLOCK)`
- Chunked file transfer over TCP with partial send/receive handling
- IPv4 + IPv6 compatibility via `getaddrinfo()`

## TCP vs UDP

- TCP:
  - Connection-oriented
  - Reliable, ordered byte stream
  - Used here for chat and file transfer
- UDP:
  - Connectionless datagrams
  - No built-in reliability or ordering
  - Used here for simple send/receive examples

## Blocking vs Non-Blocking

- Blocking sockets: system calls wait until work can be completed.
- Non-blocking sockets: system calls return immediately with `EAGAIN/EWOULDBLOCK` when not ready.
- This project uses non-blocking sockets and `select()` to wait for readiness safely.

## Folder Structure

```text
Socket-Programming-in-C/
|-- client.c
|-- server.c
|-- udp_sender.c
|-- udp_receiver.c
|-- utils.c
|-- utils.h
|-- Makefile
|-- README.md
|-- LICENSE
|-- .gitignore
|-- todo.md
`-- uploads/               (created at runtime)
```

## Build Instructions

Requirements:
- Linux
- GCC
- Make

Build all targets:

```bash
make
```

Strict compile flags used:

```text
-Wall -Wextra -pedantic -std=c11
```

Clean artifacts:

```bash
make clean
```

## Run Instructions

Start TCP server:

```bash
make run-server
# equivalent: ./bin/server 9090
```

Start TCP client:

```bash
make run-client
# equivalent: ./bin/client 127.0.0.1 9090
```

Useful client commands:
- `/help` show commands
- `/send /path/to/file` upload file to server
- `/quit` disconnect

UDP demos:

```bash
./bin/udp_receiver 12345
./bin/udp_sender 127.0.0.1 12345 "hello"
```

## Example Terminal Output

Server:

```text
[2026-02-15 16:00:01] [INFO] listening on [::]:9090 (non-blocking, select-based)
[2026-02-15 16:00:01] [INFO] server started. Press Ctrl+C to stop.
[2026-02-15 16:00:09] [INFO] client connected: [::1]:54022 (fd=4)
[2026-02-15 16:00:11] [INFO] file upload started by [::1]:54022: uploads/client4_notes.txt (2048 bytes)
[2026-02-15 16:00:11] [INFO] file upload completed from [::1]:54022: uploads/client4_notes.txt (2048 bytes)
```

Client:

```text
[2026-02-15 16:00:09] [INFO] connected to [::1]:9090
Type chat messages and press Enter.
Use /send <path> to upload a file, /quit to exit.
[server] welcome. Commands: normal text chat, /quit, /send <path> (from client)
hello everyone
[[::1]:54022] hello everyone
/send ./notes.txt
[2026-02-15 16:00:11] [INFO] sent file 'notes.txt' (2048 bytes)
[server] file 'notes.txt' uploaded (2048 bytes)
```

## Architecture (ASCII)

```text
                +-----------------------------+
                |      Non-blocking Client    |
 stdin -------> |  select(stdin, socket)      |
                |  /send -> FILE_BEGIN+bytes  |
                +---------------+-------------+
                                |
                                | TCP (IPv4/IPv6 via getaddrinfo)
                                v
                   +------------+-------------+
                   |     TCP Server           |
                   | select(listen + clients) |
                   | - accept new clients     |
                   | - broadcast chat lines   |
                   | - receive file chunks    |
                   +------------+-------------+
                                |
                                v
                       uploads/clientN_file
```

## Notes on Safety and Validation

- Every system call is checked.
- Client/server buffers are bounds-checked to prevent overflow.
- File names are sanitized before writing under `uploads/`.
- Malformed file headers are rejected.
- Partial sends and receives are handled correctly.

## License

This project is licensed under Apache License 2.0 (see `LICENSE`).
