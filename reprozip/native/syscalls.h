#ifndef SYSCALL_H
#define SYSCALL_H

#include "tracer.h"

void syscall_build_table(void);

int syscall_handle(struct Process *process);

#endif
