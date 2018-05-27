CC=gcc
CFLAGS=-I. -lpthread
DEPS = program.h crc64.h iprange.h cache_iprange.h cache_policy.h cache_customlist.h cache_domains.h cache_loader.h socket_srv.h
OBJ = program.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

program: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)
