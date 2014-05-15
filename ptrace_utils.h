#ifndef PTRACE_UTILS_H
#define PTRACE_UTILS_H

size_t tracee_strlen(pid_t pid, size_t ptr);

void tracee_read(pid_t pid, char *dst, size_t ptr, size_t size);

char *tracee_strdup(pid_t pid, size_t ptr);

char **tracee_strarraydup(pid_t pid, size_t ptr);

#endif
