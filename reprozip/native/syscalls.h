#ifndef SYSCALL_H
#define SYSCALL_H

#include "tracer.h"

void syscall_build_table(void);

int syscall_handle(struct Process *process);

int syscall_execve_event(struct Process *process);
int syscall_fork_event(struct Process *process, unsigned int event);

#endif
