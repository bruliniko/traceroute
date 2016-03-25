CC = gcc 
CFLAGS = -Wall -W -Wshadow -std=gnu99 
TARGETS = traceroute
 
all: traceroute

traceroute: traceroute.o

clean: 
	rm -f *.o

distclean: clean
	rm -f traceroute
