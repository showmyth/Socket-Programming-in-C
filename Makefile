CC ?= gcc
CFLAGS ?= -Wall -Wextra -pedantic -std=c11
CPPFLAGS ?= -D_POSIX_C_SOURCE=200809L

BIN_DIR := bin
TARGETS := $(BIN_DIR)/server $(BIN_DIR)/client $(BIN_DIR)/udp_sender $(BIN_DIR)/udp_receiver
COMMON_OBJ := $(BIN_DIR)/utils.o

.PHONY: all clean run-server run-client

all: $(BIN_DIR) $(TARGETS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/utils.o: utils.c utils.h | $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/server.o: server.c utils.h | $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/client.o: client.c utils.h | $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/udp_sender.o: udp_sender.c utils.h | $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/udp_receiver.o: udp_receiver.c utils.h | $(BIN_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/server: $(BIN_DIR)/server.o $(COMMON_OBJ)
	$(CC) $(CFLAGS) $^ -o $@

$(BIN_DIR)/client: $(BIN_DIR)/client.o $(COMMON_OBJ)
	$(CC) $(CFLAGS) $^ -o $@

$(BIN_DIR)/udp_sender: $(BIN_DIR)/udp_sender.o $(COMMON_OBJ)
	$(CC) $(CFLAGS) $^ -o $@

$(BIN_DIR)/udp_receiver: $(BIN_DIR)/udp_receiver.o $(COMMON_OBJ)
	$(CC) $(CFLAGS) $^ -o $@

run-server: $(BIN_DIR)/server
	./$(BIN_DIR)/server 9090

run-client: $(BIN_DIR)/client
	./$(BIN_DIR)/client 127.0.0.1 9090

clean:
	rm -rf $(BIN_DIR) uploads
