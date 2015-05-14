/* threads2.c
 *
 * A second multithreaded program.
 *
 * usage: ./threads2
 */

#include <pthread.h>
#include <stdio.h>


int search(void)
{
    int i;
    int sum = 0;
    for(i = 0; sum != 10; ++i)
    {
        int a = 1, b = 1;
        int j;
        for(j = 1; j < i; ++j)
        {
            int c = a + b;
            a = b;
            b = c;
        }
        sum += b;
    }
    return i;
}

void *funcT(void *param)
{
    char *argv[3] = {"echo", "42", NULL};
    usleep(200000);
    execvp("/bin/echo", argv);
    perror("execvp");
    return NULL;
}

int main(void)
{
    int r;
    pthread_t th;
    pthread_create(&th, NULL, funcT, NULL);

    r = search();
    /* Won't be reached */
    printf("%d\n", r);
    pthread_join(th, NULL);
    return 2;
}
