#ifndef PTRACE_UTILS_H
#define PTRACE_UTILS_H

int tracee_getptr(int mode, pid_t tid, const void *addr, void **out);
int tracee_getlong(int mode, pid_t tid, const void *addr, uint64_t *out);
int tracee_getu64(pid_t tid, const void *addr, uint64_t *out);
size_t tracee_getwordsize(int mode);

int tracee_strlen(pid_t tid, const char *str, size_t *out);

int tracee_read(pid_t tid, char *dst, const char *src, size_t size);

int tracee_strdup(pid_t tid, const char *str, char **out);

int tracee_strarraydup(int mode, pid_t tid, const char *const *argv, char ***out);
void free_strarray(char **array);

#endif
