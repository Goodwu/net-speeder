CC=gcc
CFLAGS=-O2 -g
LDFLAGS=-static -lpcap -lnet -Wl,-Bdynamic -Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2
#LDFLAGS=-lpcap -lnet

net_speeder: net_speeder.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f net_speeder net_speeder.o
