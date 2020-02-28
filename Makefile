CC=gcc
CFLAGS=-O2
LDFLAGS=-lpcap -lnet

net_speeder: net_speeder.o
	$(CC) -o $@ $^ $(LDFLAGS)
