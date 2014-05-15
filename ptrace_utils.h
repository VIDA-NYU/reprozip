#ifndef PTRACE_UTILS_H
#define PTRACE_UTILS_H

size_t tracee_strlen(pid_t pid, const char *str);

void tracee_read(pid_t pid, char *dst, const char *src, size_t size);

char *tracee_strdup(pid_t pid, const char *str);

char **tracee_strarraydup(pid_t pid, const char *const *argv);

#endif
