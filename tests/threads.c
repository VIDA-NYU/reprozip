/* threads.c
 *
 * This is a very simple threaded program.
 *
 * usage: ./threads
 */

#include <pthread.h>
#include <stdio.h>


void *func1(void *param)
{
    static retvalue = 42;
    chdir("/bin");
    usleep(100000);
    return &retvalue;
}

void *func23(void *param)
{
    usleep(500000);
    return NULL;
}

void *func4(void *param)
{
    char *argv[3] = {"echo", "42", NULL};
    usleep(200000);
    execvp("./echo", argv);
    perror("execvp");
    return NULL;
}

int main(void)
{
    pthread_t th1, th2, th3, th4;
    pthread_create(&th1, NULL, func1, NULL);
    pthread_create(&th2, NULL, func23, NULL);
    pthread_create(&th3, NULL, func23, NULL);
    pthread_create(&th4, NULL, func4, NULL);

    {
        void *retval;
        pthread_join(th1, &retval);
        if(*(int*)retval != 42)
        {
            fprintf(stderr, "Invalid return from thread 1\n");
            return 1;
        }
    }

    pthread_join(th4, NULL);
    /* Won't be reached */
    return 2;
}
