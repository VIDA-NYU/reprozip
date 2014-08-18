#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <unistd.h>


unsigned int flags2mode(int flags);

char *abspath(const char *wd, const char *path);

char *get_wd(void);

char *read_line(char *buffer, size_t *size, FILE *fp);

int path_is_dir(const char *pathname);

#endif
