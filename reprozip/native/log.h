#ifndef LOG_H
#define LOG_H

#ifdef __GNUC__

#define log_critical(s, ...) log_critical_(s "\n", ## __VA_ARGS__)
#define log_error(s, ...) log_critical_(s "\n", ## __VA_ARGS__)
#define log_warn(s, ...) log_warn_(s "\n", ## __VA_ARGS__)
#define log_info(s, ...) log_info_(s "\n", ## __VA_ARGS__)

#define log_critical_(s, ...) fprintf(stderr, "[REPROZIP] Critical: " s, \
    ## __VA_ARGS__)
#define log_error_(s, ...) fprintf(stderr, "[REPROZIP] Error: " s, \
    ## __VA_ARGS__)
#define log_warn_(s, ...) fprintf(stderr, "[REPROZIP] Warning: " s, \
    ## __VA_ARGS__)
#define log_info_(s, ...) fprintf(stderr, "[REPROZIP] " s, \
    ## __VA_ARGS__)

#else

#define log_critical(s, ...) log_critical_(s "\n", __VA_ARGS__)
#define log_error(s, ...) log_critical_(s "\n", __VA_ARGS__)
#define log_warn(s, ...) log_warn_(s "\n", __VA_ARGS__)
#define log_info(s, ...) log_info_(s "\n", __VA_ARGS__)

#define log_critical_(s, ...) fprintf(stderr, "[REPROZIP] Critical: " s, \
    __VA_ARGS__)
#define log_error_(s, ...) fprintf(stderr, "[REPROZIP] Error: " s, \
    __VA_ARGS__)
#define log_warn_(s, ...) fprintf(stderr, "[REPROZIP] Warning: " s, \
    __VA_ARGS__)
#define log_info_(s, ...) fprintf(stderr, "[REPROZIP] " s, \
    __VA_ARGS__)

#endif

#endif
