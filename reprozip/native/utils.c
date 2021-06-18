#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "database.h"
#include "log.h"


unsigned int flags2mode(int flags)
{
    unsigned int mode = 0;
    if(!O_RDONLY)
    {
        if(flags & O_WRONLY)
            mode |= FILE_WRITE;
        else if(flags & O_RDWR)
            mode |= FILE_READ | FILE_WRITE;
        else
            mode |= FILE_READ;
    }
    else if(!O_WRONLY)
    {
        if(flags & O_RDONLY)
            mode |= FILE_READ;
        else if(flags & O_RDWR)
            mode |= FILE_READ | FILE_WRITE;
        else
            mode |= FILE_WRITE;
    }
    else
    {
        if( (flags & (O_RDONLY | O_WRONLY)) == (O_RDONLY | O_WRONLY) )
            log_error(0, "encountered bogus open() flags O_RDONLY|O_WRONLY");
            /* Carry on anyway */
        if(flags & O_RDONLY)
            mode |= FILE_READ;
        if(flags & O_WRONLY)
            mode |= FILE_WRITE;
        if(flags & O_RDWR)
            mode |= FILE_READ | FILE_WRITE;
        if( (mode & FILE_READ) && (mode & FILE_WRITE) && (flags & O_TRUNC) )
            /* If O_TRUNC is set, consider this a write */
            mode &= ~FILE_READ;
    }
    return mode;
}

char *abspath(const char *wd, const char *path)
{
    size_t len_wd = strlen(wd);
    if(wd[len_wd-1] == '/')
    {
        /* LCOV_EXCL_START : We usually get canonical path names, so we don't
         * run into this one */
        char *result = malloc(len_wd + strlen(path) + 1);
        memcpy(result, wd, len_wd);
        strcpy(result + len_wd, path);
        return result;
        /* LCOV_EXCL_STOP */
    }
    else
    {
        char *result = malloc(len_wd + 1 + strlen(path) + 1);
        memcpy(result, wd, len_wd);
        result[len_wd] = '/';
        strcpy(result + len_wd + 1, path);
        return result;
    }
}

char *get_wd(void)
{
    /* PATH_MAX has issues, don't use it */
    size_t size = 1024;
    char *path;
    for(;;)
    {
        path = malloc(size);
        if(getcwd(path, size) != NULL)
            return path;
        else
        {
            if(errno != ERANGE)
            {
                /* LCOV_EXCL_START : getcwd() really shouldn't fail */
                free(path);
                log_error(0, "getcwd failed: %s", strerror(errno));
                return strdup("/UNKNOWN");
                /* LCOV_EXCL_STOP */
            }
            free(path);
            size <<= 1;
        }
    }
}

char *read_line(char *buffer, size_t *size, FILE *fp)
{
    size_t pos = 0;
    if(buffer == NULL)
    {
        *size = 4096;
        buffer = malloc(*size);
    }
    for(;;)
    {
        char c;
        {
            int t = getc(fp);
            if(t == EOF)
            {
                free(buffer);
                return NULL;
            }
            c = t;
        }
        if(c == '\n')
        {
            buffer[pos] = '\0';
            return buffer;
        }
        else
        {
            if(pos + 1 >= *size)
            {
                *size <<= 2;
                buffer = realloc(buffer, *size);
            }
            buffer[pos++] = c;
        }
    }
}

int path_is_dir(const char *pathname)
{
    struct stat buf;
    if(lstat(pathname, &buf) != 0)
    {
        /* LCOV_EXCL_START : shouldn't happen because a tracer process just
         * accessed it */
        log_error(0, "error stat()ing %s: %s", pathname, strerror(errno));
        return 0;
        /* LCOV_EXCL_STOP */
    }
    return S_ISDIR(buf.st_mode)?1:0;
}
