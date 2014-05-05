CC=gcc
LIBS=
CFLAGS=-W -Wall -Wextra -pedantic

OBJS=tracer.o database.o

.PHONY: all clean

all: tracer

clean:
	rm -f $(OBJS)

tracer: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) -lsqlite3 -lrt

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
