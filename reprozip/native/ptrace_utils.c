#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "ptrace_utils.h"


static long tracee_getword(pid_t tid, const void *addr)
{
    long res;
    errno = 0;
    res = ptrace(PTRACE_PEEKDATA, tid, addr, NULL);
    if(errno)
    {
        log_error_("tracee_getword() failed: ");
        perror(NULL);
        return 0;
    }
    return res;
}

static void *tracee_getptr(pid_t tid, const void *addr)
{
    return (void*)tracee_getword(tid, addr);
}

size_t tracee_strlen(pid_t tid, const char *str)
{
    uintptr_t ptr = (uintptr_t)str;
    size_t j = ptr % WORD_SIZE;
    uintptr_t i = ptr - j;
    size_t size = 0;
    int done = 0;
    for(; !done; i += WORD_SIZE)
    {
        unsigned long data = tracee_getword(tid, (const void*)i);
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

void tracee_read(pid_t tid, char *dst, const char *src, size_t size)
{
    uintptr_t ptr = (uintptr_t)src;
    size_t j = ptr % WORD_SIZE;
    uintptr_t i = ptr - j;
    uintptr_t end = ptr + size;
    for(; i < end; i += WORD_SIZE)
    {
        unsigned long data = tracee_getword(tid, (const void*)i);
        for(; j < WORD_SIZE && i + j < end; ++j)
            *dst++ = data >> (8 * j);
        j = 0;
    }
}

char *tracee_strdup(pid_t tid, const char *str)
{
    size_t length = tracee_strlen(tid, str);
    char *res = malloc(length + 1);
    tracee_read(tid, res, str, length);
    res[length] = '\0';
    return res;
}

char **tracee_strarraydup(pid_t tid, const char *const *argv)
{
    char **array;
    /* Reads number of pointers in pointer array */
    size_t nb_args = 0;
    {
        const char *const *a = argv;
        /* xargv = *a */
        const char *xargv = tracee_getptr(tid, a);
        while(xargv != NULL)
        {
            ++nb_args;
            ++a;
            xargv = tracee_getptr(tid, a);
        }
    }
    /* Allocs pointer array */
    array = malloc((nb_args + 1) * sizeof(char*));
    /* Dups array elements */
    {
        size_t i = 0;
        /* xargv = argv[0] */
        const char *xargv = tracee_getptr(tid, argv);
        while(xargv != NULL)
        {
            array[i] = tracee_strdup(tid, xargv);
            ++i;
            /* xargv = argv[i] */
            xargv = tracee_getptr(tid, argv + i);
        }
        array[i] = NULL;
    }
    return array;
}

void free_strarray(char **array)
{
    char **ptr = array;
    while(*ptr)
    {
        free(*ptr);
        ++ptr;
    }
    free(array);
}
