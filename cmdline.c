#include <stdio.h>

#include <unistd.h>

#include "tracer.h"


int main(int argc, char **argv)
{
    int exit_status;
    unlink("./database.sqlite3");
    if(fork_and_trace(argv[1], argc - 1, argv + 1, "./database.sqlite3",
                      &exit_status) != 0)
        return 255; /* tracer failed */
    else
    {
        if(exit_status & 0x0100) /* killed by a signal */
        {
            fprintf(stderr, "Process was killed by signal %d\n",
                    exit_status & 0xFF);
            return 2;
        }
        else
        {
            fprintf(stderr, "Process returned %d\n", exit_status & 0xFF);
            return exit_status;
        }
    }
}
