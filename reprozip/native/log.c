#include <stdarg.h>
#include <time.h>

#include "log.h"


void log_real_(pid_t tid, const char *tag, const char *format, ...)
{
    va_list args;
    float t;
    va_start(args, format);
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        t = (ts.tv_sec * 1.0f) + (ts.tv_nsec * 0.000000001f);
    }
    if(tag != NULL)
        fprintf(stderr, "[REPROZIP] %f %s: ", t, tag);
    else
        fprintf(stderr, "[REPROZIP] %f ", t);
    if(tid > 0)
        fprintf(stderr, "[%d] ", tid);
    vfprintf(stderr, format, args);
    va_end(args);
}
