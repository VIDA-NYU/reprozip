/* exec_echo.c
 *
 * This is a very simple program that executes /bin/echo to display a message.
 * Used to try an i386 -> x64 transition.
 *
 * usage: ./exec_echo somestr
 */

#include <unistd.h>


int main(int argc, char **argv, char **envp)
{
    if(argc != 2)
        return 2;

    {
        char *args[] = {"echo", argv[1], NULL};
        execve("/bin/echo", args, envp);
    }

    return 1;
}
