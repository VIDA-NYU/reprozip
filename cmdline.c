#include <stdio.h>

#include <unistd.h>

#include "tracer.h"


int main(int argc, char **argv)
{
    fprintf(stderr, "Debug mode, using database on disk\n");
    unlink("./database.sqlite3");
    return fork_and_trace(argc - 1, argv + 1, "./database.sqlite3");
}
