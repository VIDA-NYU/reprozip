/* vfork.c
 *
 * This just calls vfork() then execve().
 *
 * usage: ./vfork
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


int main(void)
{
    pid_t res = vfork();
    if(res == 0)
    {
        char *args[] = {"echo", "hello", NULL};
        execv("/bin/echo", args);
    }
    else if(res > 0)
    {
        int status;
        waitpid(res, &status, 0);
        if(WIFEXITED(status))
            return 0;
        else
            return 1;
    }
    else
    {
        perror("vfork");
        return 2;
    }
}
