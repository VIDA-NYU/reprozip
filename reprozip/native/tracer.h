#ifndef TRACER_H
#define TRACER_H

#include "config.h"


int fork_and_trace(const char *binary, int argc, char **argv,
                   const char *database_path, int *exit_status);


/* This is NOT a union because sign-extension rules depend on actual register
 * sizes. */
typedef struct S_register_type {
    signed long int i;
    unsigned long int u;
    void *p;
} register_type;


#define PROCESS_ARGS 6

struct ExecveInfo {
    char *binary;
    char **argv;
    char **envp;
};

void free_execve_info(struct ExecveInfo *execi);

struct ThreadGroup {
    pid_t tgid;
    char *wd;
    unsigned int refs;
};

struct Process {
    unsigned int identifier;
    unsigned int mode;
    struct ThreadGroup *threadgroup;
    pid_t tid;
    int status;
    unsigned int flags;
    int in_syscall;
    int current_syscall;
    register_type retvalue;
    register_type params[PROCESS_ARGS];
    struct ExecveInfo *execve_info;
};

#define PROCSTAT_FREE       0   /* unallocated entry in table */
#define PROCSTAT_ALLOCATED  1   /* fork() done but not yet attached */
#define PROCSTAT_ATTACHED   2   /* running process */
#define PROCSTAT_UNKNOWN    3   /* attached but no corresponding fork() call
                                 * has finished yet */

#define MODE_I386           1
#define MODE_X86_64         2   /* In x86_64 mode, syscalls might be native x64
                                 * or x32 */

#define PROCFLAG_EXECD      1   /* Process is coming out of execve */
#define PROCFLAG_FORKING    2   /* Process is spawning another with
                                 * fork/vfork/clone */
#define PROCFLAG_OPEN_EXIST 4   /* Process is opening a file that exists */

/* FIXME : This is only exposed because of execve() workaround */
extern struct Process **processes;
extern size_t processes_size;


struct Process *trace_find_process(pid_t tid);

struct Process *trace_get_empty_process(void);

struct ThreadGroup *trace_new_threadgroup(pid_t tgid, char *wd);

void trace_free_process(struct Process *process);

void trace_count_processes(unsigned int *p_nproc, unsigned int *p_unknown);

int trace_add_files_from_proc(unsigned int process, pid_t tid,
                              const char *binary);

#endif
