#ifndef PTRACE_UTILS_H
#define PTRACE_UTILS_H

size_t tracee_strlen(pid_t tid, const char *str);

void tracee_read(pid_t tid, char *dst, const char *src, size_t size);

char *tracee_strdup(pid_t tid, const char *str);

char **tracee_strarraydup(pid_t tid, const char *const *argv);
void free_strarray(char **array);

#endif
