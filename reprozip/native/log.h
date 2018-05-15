#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <time.h>

#include <sys/time.h>
#include <sys/types.h>


extern int logging_level;

int log_setup(void);
void log_real_(pid_t tid, int lvl, const char *format, ...);


#ifdef __GNUC__

#define log_critical(i, s, ...) log_real_(i, 50, s, ## __VA_ARGS__)
#define log_error(i, s, ...) log_real_(i, 40, s, ## __VA_ARGS__)
#define log_warn(i, s, ...) log_real_(i, 30, s, ## __VA_ARGS__)
#define log_info(i, s, ...) log_real_(i, 20, s, ## __VA_ARGS__)
#define log_debug(i, s, ...) log_real_(i, 10, s, ## __VA_ARGS__)

#else

#define log_critical(i, s, ...) log_real_(i, 50, s, __VA_ARGS__)
#define log_error(i, s, ...) log_real_(i, 40, s, __VA_ARGS__)
#define log_warn(i, s, ...) log_real_(i, 30, s, __VA_ARGS__)
#define log_info(i, s, ...) log_real_(i, 20, s, __VA_ARGS__)
#define log_debug(i, s, ...) log_real_(i, 10, s, __VA_ARGS__)
#endif

#endif
