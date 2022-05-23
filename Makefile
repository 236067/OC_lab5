
CC = gcc
CFLAGS = -g -std=gnu99


all: server client


server: server.c
	$(CC) $(CFLAGS) server.c -o server -lpthread

client: client.c
	$(CC) $(CFLAGS) client.c -o client


clean:
	rm -f client server

