#ifndef PTRACE_UTILS_H
#define PTRACE_UTILS_H

void *tracee_getptr(int mode, pid_t tid, const void *addr);
uint64_t tracee_getlong(int mode, pid_t tid, const void *addr);
size_t tracee_getwordsize(int mode);

size_t tracee_strlen(pid_t tid, const char *str);

void tracee_read(pid_t tid, char *dst, const char *src, size_t size);

char *tracee_strdup(pid_t tid, const char *str);

char **tracee_strarraydup(int mode, pid_t tid, const char *const *argv);
void free_strarray(char **array);

#endif
