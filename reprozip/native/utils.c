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


extern int trace_verbosity;


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
            fprintf(stderr, "Error: encountered bogus open() flags "
                    "O_RDONLY|O_WRONLY\n");
            /* Carry on anyway */
        if(flags & O_RDONLY)
            mode |= FILE_READ;
        if(flags & O_WRONLY)
            mode |= FILE_WRITE;
        if(flags & O_RDWR)
            mode |= FILE_READ | FILE_WRITE;
    }
    return mode;
}

char *abspath(const char *wd, const char *path)
{
    size_t len_wd = strlen(wd);
#ifdef DEBUG
    fprintf(stderr, "abspath(%s, %s) = ", wd, path);
#endif
    if(wd[len_wd-1] == '/')
    {
        char *result = malloc(len_wd + strlen(path) + 1);
        memcpy(result, wd, len_wd);
        strcpy(result + len_wd, path);
#ifdef DEBUG
        fprintf(stderr, "%s\n", result);
#endif
        return result;
    }
    else
    {
        char *result = malloc(len_wd + 1 + strlen(path) + 1);
        memcpy(result, wd, len_wd);
        result[len_wd] = '/';
        strcpy(result + len_wd + 1, path);
#ifdef DEBUG
        fprintf(stderr, "%s\n", result);
#endif
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
                free(path);
                perror("getcwd failed");
                return strdup("/UNKNOWN");
            }
            free(path);
            size <<= 1;
        }
    }
}

char *get_p_wd(pid_t pid)
{
    /* PATH_MAX has issues, don't use it */
    size_t size = 1024;
    char *path;
    char dummy;
    char *proclink;
    int len = snprintf(&dummy, 1, "/proc/%d/cwd", pid);
    proclink = malloc(len + 1);
    snprintf(proclink, len + 1, "/proc/%d/cwd", pid);
    for(;;)
    {
        int ret;
        path = malloc(size);
        ret = readlink(proclink, path, size);
        if(ret < 0)
        {
            free(path);
            perror("readlink failed");
            return strdup("/UNKNOWN");
        }
        else if((size_t)ret >= size)
        {
            free(path);
            size <<= 1;
        }
        else
        {
            path[ret] = '\0';
            return path;
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
        if(trace_verbosity >= 1)
        {
            fprintf(stderr, "Error stat()ing %s", pathname);
            perror("");
        }
        return 0;
    }
    return S_ISDIR(buf.st_mode)?1:0;
}
