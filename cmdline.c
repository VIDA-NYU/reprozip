#include <stdio.h>

#include <unistd.h>

#include "tracer.h"


int main(int argc, char **argv)
{
    unlink("./database.sqlite3");
    return fork_and_trace(argv[1], argc - 1, argv + 1, "./database.sqlite3");
}
