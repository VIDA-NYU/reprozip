#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <time.h>

#include <sys/time.h>
#include <sys/types.h>


int log_open_file(const char *filename);
void log_close_file(void);


void log_real_(pid_t tid, const char *tag, int lvl, const char *format, ...);


#ifdef __GNUC__

#define log_critical(i, s, ...) log_critical_(i, s "\n", ## __VA_ARGS__)
#define log_error(i, s, ...) log_critical_(i, s "\n", ## __VA_ARGS__)
#define log_warn(i, s, ...) log_warn_(i, s "\n", ## __VA_ARGS__)
#define log_info(i, s, ...) log_info_(i, s "\n", ## __VA_ARGS__)
#define log_debug(i, s, ...) log_debug_(i, s "\n", ## __VA_ARGS__)

#define log_critical_(i, s, ...) log_real_(i, "CRITICAL", 0, s, ## __VA_ARGS__)
#define log_error_(i, s, ...) log_real_(i, "ERROR", 0, s, ## __VA_ARGS__)
#define log_warn_(i, s, ...) log_real_(i, "WARNING", 1, s, ## __VA_ARGS__)
#define log_info_(i, s, ...) log_real_(i, "INFO", 2, s, ## __VA_ARGS__)
#define log_debug_(i, s, ...) log_real_(i, "DEBUG", 3, s, ## __VA_ARGS__)

#else

#define log_critical(i, s, ...) log_critical_(i, s "\n", __VA_ARGS__)
#define log_error(i, s, ...) log_critical_(i, s "\n", __VA_ARGS__)
#define log_warn(i, s, ...) log_warn_(i, s "\n", __VA_ARGS__)
#define log_info(i, s, ...) log_info_(i, s "\n", __VA_ARGS__)
#define log_debug(i, s, ...) log_debug_(i, s "\n", __VA_ARGS__)

#define log_critical_(i, s, ...) log_real_(i, "CRITICAL", 0, s, __VA_ARGS__)
#define log_error_(i, s, ...) log_real_(i, "ERROR", 0, s, __VA_ARGS__)
#define log_warn_(i, s, ...) log_real_(i, "WARNING", 1, s, __VA_ARGS__)
#define log_info_(i, s, ...) log_real_(i, "INFO", 2, s, __VA_ARGS__)
#define log_debug_(i, s, ...) log_real_(i, "DEBUG", 3, s, __VA_ARGS__)
#endif

#endif
