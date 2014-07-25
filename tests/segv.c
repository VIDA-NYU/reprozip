/* segv.c
 *
 * This program will spawn a process that will seg fault before the main
 * process finishes.
 *
 * usage: ./segv
 */

#include <unistd.h>


int main(int argc, char **argv)
{
    pid_t child = fork();
    if(child < 0)
        return 1;
    else if(child == 0)
    {
        char *ptr = NULL;
        *ptr = 42; /* segv */
        return 0;
    }
    else
    {
        usleep(100000);
        return 0;
    }
}
