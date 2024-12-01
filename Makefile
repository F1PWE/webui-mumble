CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lwebsockets -lssl -lcrypto -ljansson

SERVER_SRC = src/server/main.c
SERVER_OBJ = $(SERVER_SRC:.c=.o)
SERVER_BIN = mumble-webui-server

.PHONY: all clean

all: $(SERVER_BIN)

$(SERVER_BIN): $(SERVER_OBJ)
	$(CC) $(SERVER_OBJ) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(SERVER_OBJ) $(SERVER_BIN) 