#include <stdarg.h>
#include <time.h>

#include "log.h"


void log_real_(pid_t tid, const char *tag, const char *format, ...)
{
    va_list args;
    char datestr[13]; /* HH:MM:SS.mmm */
    va_start(args, format);
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        strftime(datestr, 13, "%H:%M:%S", localtime(&tv.tv_sec));
        sprintf(datestr+8, ".%03d", tv.tv_usec / 1000);
    }
    fprintf(stderr, "[REPROZIP] %s %s: ", datestr, tag);
    if(tid > 0)
        fprintf(stderr, "[%d] ", tid);
    vfprintf(stderr, format, args);
    va_end(args);
}
