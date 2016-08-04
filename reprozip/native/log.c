#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"


extern int trace_verbosity;


static FILE *logfile = NULL;


int log_open_file(const char *filename)
{
    assert(logfile == NULL);
    logfile = fopen(filename, "ab");
    if(logfile == NULL)
    {
        log_critical(0, "couldn't open log file: %s", strerror(errno));
        return -1;
    }
    return 0;
}


void log_close_file(void)
{
    if(logfile != NULL)
    {
        fclose(logfile);
        logfile = NULL;
    }
}


void log_real_(pid_t tid, const char *tag, int lvl, const char *format, ...)
{
    va_list args;
    char datestr[13]; /* HH:MM:SS.mmm */
    static char *buffer = NULL;
    static size_t bufsize = 4096;
    int length;
    if(buffer == NULL)
        buffer = malloc(bufsize);
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        strftime(datestr, 13, "%H:%M:%S", localtime(&tv.tv_sec));
        sprintf(datestr+8, ".%03u", (unsigned int)(tv.tv_usec / 1000));
    }
    va_start(args, format);
    length = vsnprintf(buffer, bufsize, format, args);
    va_end(args);
    if(length >= bufsize)
    {
        while(length >= bufsize)
            bufsize *= 2;
        free(buffer);
        buffer = malloc(bufsize);
        va_start(args, format);
        length = vsnprintf(buffer, bufsize, format, args);
        va_end(args);
    }

    if(trace_verbosity >= lvl)
    {
        fprintf(stderr, "[REPROZIP] %s %s: ", datestr, tag);
        if(tid > 0)
            fprintf(stderr, "[%d] ", tid);
        fwrite(buffer, length, 1, stderr);
    }
    if(logfile && lvl <= 2)
    {
        fprintf(logfile, "[REPROZIP] %s %s: ", datestr, tag);
        if(tid > 0)
            fprintf(logfile, "[%d] ", tid);
        fwrite(buffer, length, 1, logfile);
        fflush(logfile);
    }
}
