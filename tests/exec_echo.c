/* exec_echo.c
 *
 * This is a very simple program that executes /bin/echo to display a message.
 * Used to try an i386 -> x64 transition.
 *
 * usage: ./exec_echo
 */

#include <unistd.h>


int main(int argc, char **argv, char **envp)
{
    char *args[] = {"echo", "42", NULL};
    execve("/bin/echo", args, envp);

    return 1;
}
