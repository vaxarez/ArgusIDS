CC = gcc
CFLAGS = -Wall -g

OBJS = main.o network_monitor.o signature_detection.o utils.o

all: daemon

daemon: $(OBJS)
	$(CC) $(CFLAGS) -o daemon $(OBJS) -lpcap

clean:
	rm -f *.o daemon
