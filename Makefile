CC=gcc
CFLAGS=-O2
LDFLAGS=-static -lpcap -lnet -Wl,-Bdynamic

net_speeder: net_speeder.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f net_speeder net_speeder.o
