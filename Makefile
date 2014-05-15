# Note that this file is used to build the standalone version of the tracer,
# NOT the Python package! (which is built via the standard setup.py script,
# using setuptools)

CC=gcc
LIBS=
CFLAGS=-W -Wall -Wextra -Wstrict-prototypes -pedantic

OBJS=tracer.o database.o cmdline.o ptrace_utils.o

.PHONY: all clean

all: tracer

clean:
	rm -f $(OBJS)

tracer: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) -lsqlite3 -lrt

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
