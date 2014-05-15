#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "ptrace_utils.h"


size_t tracee_strlen(pid_t pid, size_t ptr)
{
    size_t j = ptr % WORD_SIZE;
    size_t i = ptr - j;
    size_t size = 0;
    int done = 0;
    for(; !done; i += WORD_SIZE)
    {
        unsigned int data = ptrace(PTRACE_PEEKDATA, pid, i, NULL);
        for(; !done && j < WORD_SIZE; ++j)
        {
            unsigned char byte = data >> (8 * j);
            if(byte == 0)
                done = 1;
            else
                ++size;
        }
        j = 0;
    }
    return size;
}

void tracee_read(pid_t pid, char *dst, size_t ptr, size_t size)
{
    size_t j = ptr % WORD_SIZE;
    size_t i = ptr - j;
    size_t end = ptr + size;
    for(; i < end; i += WORD_SIZE)
    {
        unsigned int data = ptrace(PTRACE_PEEKDATA, pid, i, NULL);
        for(; j < WORD_SIZE && i + j < end; ++j)
            *dst++ = data >> (8 * j);
        j = 0;
    }
}

char *tracee_strdup(pid_t pid, size_t ptr)
{
    size_t length = tracee_strlen(pid, ptr);
    char *str = malloc(length + 1);
    tracee_read(pid, str, ptr, length);
    str[length] = '\0';
    return str;
}

char **tracee_strarraydup(pid_t pid, size_t ptr)
{
    char **array;
    /* Reads number of pointers in pointer array */
    size_t nb_args = 0;
    const char *const *const argv = (void*)ptr;
    {
        const char *const *a = argv;
        /* xargv = *a */
        const char *xargv = (void*)ptrace(PTRACE_PEEKDATA, pid, a, NULL);
        while(xargv != NULL)
        {
            ++nb_args;
            ++a;
            xargv = (void*)ptrace(PTRACE_PEEKDATA, pid, a, NULL);
        }
    }
    /* Allocs pointer array */
    array = malloc((nb_args + 1) * sizeof(char*));
    /* Dups array elements */
    {
        size_t i = 0;
        /* xargv = argv[0] */
        const char *xargv = (void*)ptrace(PTRACE_PEEKDATA, pid, argv, NULL);
        while(xargv != NULL)
        {
            array[i] = tracee_strdup(pid, (size_t)xargv);
            ++i;
            /* xargv = argv[i] */
            xargv = (void*)ptrace(PTRACE_PEEKDATA, pid, argv + i, NULL);
        }
        array[i] = NULL;
    }
    return array;
}
