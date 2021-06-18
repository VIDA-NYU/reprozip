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
#include "tracer.h"


static long tracee_getword(pid_t tid, const void *addr)
{
    long res;
    errno = 0;
    res = ptrace(PTRACE_PEEKDATA, tid, addr, NULL);
    if(errno)
    {
        /* LCOV_EXCL_START : We only do that on things that went through the
         * kernel successfully, and so should be valid. The exception is
         * execve(), which will dup arguments when entering the syscall */
        log_error(tid, "tracee_getword() failed: %s", strerror(errno));
        return 0;
        /* LCOV_EXCL_STOP */
    }
    return res;
}

void *tracee_getptr(int mode, pid_t tid, const void *addr)
{
    if(mode == MODE_I386)
    {
        /* Pointers are 32 bits */
        uint32_t ptr;
        tracee_read(tid, (void*)&ptr, addr, sizeof(ptr));
        return (void*)(uint64_t)ptr;
    }
    else /* mode == MODE_X86_64 */
    {
        /* Pointers are 64 bits */
        uint64_t ptr;
        tracee_read(tid, (void*)&ptr, addr, sizeof(ptr));
        return (void*)ptr;
    }
}

uint64_t tracee_getlong(int mode, pid_t tid, const void *addr)
{
    if(mode == MODE_I386)
    {
        /* Longs are 32 bits */
        uint32_t val;
        tracee_read(tid, (void*)&val, addr, sizeof(val));
        return (uint64_t)val;
    }
    else /* mode == MODE_X86_64 */
    {
        /* Longs are 64 bits */
        uint64_t val;
        tracee_read(tid, (void*)&val, addr, sizeof(val));
        return val;
    }
}

size_t tracee_getwordsize(int mode)
{
    if(mode == MODE_I386)
        /* Pointers are 32 bits */
        return 4;
    else /* mode == MODE_X86_64 */
        /* Pointers are 64 bits */
        return 8;
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

char **tracee_strarraydup(int mode, pid_t tid, const char *const *argv)
{
    /* FIXME : This is probably broken on x32 */
    char **array;
    /* Reads number of pointers in pointer array */
    size_t nb_args = 0;
    {
        const char *const *a = argv;
        /* xargv = *a */
        const char *xargv = tracee_getptr(mode, tid, a);
        while(xargv != NULL)
        {
            ++nb_args;
            ++a;
            xargv = tracee_getptr(mode, tid, a);
        }
    }
    /* Allocs pointer array */
    array = malloc((nb_args + 1) * sizeof(char*));
    /* Dups array elements */
    {
        size_t i = 0;
        /* xargv = argv[0] */
        const char *xargv = tracee_getptr(mode, tid, argv);
        while(xargv != NULL)
        {
            array[i] = tracee_strdup(tid, xargv);
            ++i;
            /* xargv = argv[i] */
            xargv = tracee_getptr(mode, tid, argv + i);
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
