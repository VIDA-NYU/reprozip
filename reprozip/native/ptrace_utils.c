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


static int tracee_getword(pid_t tid, const void *addr, long *out)
{
    errno = 0;
    *out = ptrace(PTRACE_PEEKDATA, tid, addr, NULL);
    if(errno)
    {
        /* LCOV_EXCL_START : We only do that on things that went through the
         * kernel successfully, and so should be valid. The exception is
         * execve(), which will dup arguments when entering the syscall */
        log_error(tid, "tracee_getword() failed: %s", strerror(errno));
        *out = 0;
        return -1;
        /* LCOV_EXCL_STOP */
    }
    return 0;
}

int tracee_getptr(int mode, pid_t tid, const void *addr, void **out)
{
    if(mode == MODE_I386)
    {
        /* Pointers are 32 bits */
        uint32_t ptr;
        tracee_read(tid, (void*)&ptr, addr, sizeof(ptr));
        *out = (void*)(uint64_t)ptr;
        return 0;
    }
    else /* mode == MODE_X86_64 */
    {
        /* Pointers are 64 bits */
        uint64_t ptr;
        tracee_read(tid, (void*)&ptr, addr, sizeof(ptr));
        *out = (void*)ptr;
        return 0;
    }
}

int tracee_getlong(int mode, pid_t tid, const void *addr, uint64_t *out)
{
    if(mode == MODE_I386)
    {
        /* Longs are 32 bits */
        uint32_t val;
        tracee_read(tid, (void*)&val, addr, sizeof(val));
        *out = (uint64_t)val;
        return 0;
    }
    else /* mode == MODE_X86_64 */
    {
        /* Longs are 64 bits */
        uint64_t val;
        *out = tracee_read(tid, (void*)&val, addr, sizeof(val));
        return 0;
    }
}

int tracee_getu64(pid_t tid, const void *addr, uint64_t *out)
{
    return tracee_read(tid, (void*)out, addr, sizeof(*out));
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

int tracee_strlen(pid_t tid, const char *str, size_t *out)
{
    uintptr_t ptr = (uintptr_t)str;
    size_t j = ptr % WORD_SIZE;
    uintptr_t i = ptr - j;
    *out = 0;
    int done = 0;
    for(; !done; i += WORD_SIZE)
    {
        unsigned long data;
        if(tracee_getword(tid, (const void*)i, (long*)&data) != 0) {
            return -1;
        }
        for(; !done && j < WORD_SIZE; ++j)
        {
            unsigned char byte = data >> (8 * j);
            if(byte == 0)
                done = 1;
            else
                ++*out;
        }
        j = 0;
    }
    return 0;
}

int tracee_read(pid_t tid, char *dst, const char *src, size_t size)
{
    uintptr_t ptr = (uintptr_t)src;
    size_t j = ptr % WORD_SIZE;
    uintptr_t i = ptr - j;
    uintptr_t end = ptr + size;
    for(; i < end; i += WORD_SIZE)
    {
        unsigned long data;
        if(tracee_getword(tid, (const void*)i, (long*)&data) != 0) {
            return -1;
        }
        for(; j < WORD_SIZE && i + j < end; ++j)
            *dst++ = data >> (8 * j);
        j = 0;
    }
    return 0;
}

int tracee_strdup(pid_t tid, const char *str, char **out)
{
    size_t length;
    if(tracee_strlen(tid, str, &length) != 0) {
        return -1;
    }
    *out = malloc(length + 1);
    if(tracee_read(tid, *out, str, length) != 0) {
        free(*out);
        *out = NULL;
        return -1;
    }
    (*out)[length] = '\0';
    return 0;
}

int tracee_strarraydup(int mode, pid_t tid, const char *const *argv, char ***out)
{
    /* FIXME : This is probably broken on x32 */
    /* Reads number of pointers in pointer array */
    size_t nb_args = 0;
    {
        const char *const *a = argv;
        /* xargv = *a */
        const char *xargv;
        if(tracee_getptr(mode, tid, a, (void**)&xargv) != 0) {
            return -1;
        }
        while(xargv != NULL)
        {
            ++nb_args;
            ++a;
            if(tracee_getptr(mode, tid, a, (void**)&xargv) != 0) {
                return -1;
            }
        }
    }
    /* Allocs pointer array */
    *out = malloc((nb_args + 1) * sizeof(char*));
    **out = NULL;
    /* Dups array elements */
    {
        size_t i = 0;
        /* xargv = argv[0] */
        const char *xargv;
        if(tracee_getptr(mode, tid, argv, (void**)&xargv) != 0) {
            goto cleanup;
        }
        while(xargv != NULL)
        {
            if(tracee_strdup(tid, xargv, &(*out)[i]) != 0) {
                goto cleanup;
            }
            ++i;
            (*out)[i] = NULL;
            /* xargv = argv[i] */
            if(tracee_getptr(mode, tid, argv + i, (void**)&xargv) != 0) {
                goto cleanup;
            }
        }
    }
    return 0;

cleanup:
    free_strarray(*out);
    *out = NULL;
    return -1;
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
