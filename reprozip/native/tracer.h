#ifndef TRACER_H
#define TRACER_H

#include "config.h"


int fork_and_trace(const char *binary, int argc, char **argv,
                   const char *database_path, int *exit_status);


extern int trace_verbosity;


/* This is NOT a union because sign-extension rules depend on actual register
 * sizes. */
typedef struct S_register_type {
    signed long int i;
    unsigned long int u;
    void *p;
} register_type;


struct Process {
    unsigned int identifier;
#ifdef X86_64
    unsigned int mode;
#endif
    pid_t tid;
    pid_t tgid;
    int status;
    int in_syscall;
    int current_syscall;
    char *wd;
    register_type retvalue;
    register_type params[6];
    void *syscall_info;
};

#define PROCESS_FREE        0   /* unallocated entry in table */
#define PROCESS_ALLOCATED   1   /* fork() done but not yet attached */
#define PROCESS_ATTACHED    2   /* running process */
#define PROCESS_UNKNOWN     3   /* attached but no corresponding fork() call
                                 * has finished yet */

#define MODE_I386           1
#define MODE_X86_64         2   /* In x86_64 mode, syscalls might be native x64
                                 * or x32 */

/* FIXME : This is only exposed because of execve() workaround */
extern struct Process **processes;
extern size_t processes_size;


struct Process *trace_find_process(pid_t tid);

struct Process *trace_get_empty_process(void);

void trace_count_processes(unsigned int *p_nproc, unsigned int *p_unknown);

int trace_add_files_from_proc(unsigned int process, pid_t tid,
                              const char *binary);

#endif
