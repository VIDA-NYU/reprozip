#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "database.h"
#include "ptrace_utils.h"
#include "utils.h"


#define PROCESS_FREE        0
#define PROCESS_ALLOCATED   1
#define PROCESS_ATTACHED    2

struct Process {
    unsigned int identifier;
    pid_t pid;
    int status;
    int in_syscall;
    int current_syscall;
    char *wd;
    register_type retvalue;
    register_type params[6];
    void *syscall_info;
};

struct ExecveInfo {
    char *binary;
    char **argv;
    char **envp;
};

struct Process **processes = NULL;
size_t processes_size;

struct Process *trace_find_process(pid_t pid)
{
    size_t i;
    for(i = 0; i < processes_size; ++i)
    {
        if(processes[i]->status != PROCESS_FREE && processes[i]->pid == pid)
            return processes[i];
    }
    return NULL;
}

struct Process *trace_get_empty_process(void)
{
    size_t i;
    for(i = 0; i < processes_size; ++i)
    {
        if(processes[i]->status == PROCESS_FREE)
            return processes[i];
    }

    /* Allocate more! */
    {
        struct Process *pool;
        size_t prev_size = processes_size;
        processes_size *= 2;
        pool = malloc((processes_size - prev_size) * sizeof(*pool));
        processes = realloc(processes, processes_size * sizeof(*processes));
        for(; i < processes_size; ++i)
        {
            processes[i] = pool++;
            processes[i]->status = PROCESS_FREE;
            processes[i]->in_syscall = 0;
            processes[i]->current_syscall = -1;
            processes[i]->syscall_info = NULL;
        }
        return processes[prev_size];
    }
}

int trace_add_files_from_proc(unsigned int process, pid_t pid,
                              const char *binary)
{
    FILE *fp;
    char dummy;
    char *line = NULL;
    size_t length = 0;
    char previous_path[4096] = "";

    const char *const fmt = "/proc/%d/maps";
    int len = snprintf(&dummy, 1, fmt, pid);
    char *procfile = malloc(len + 1);
    snprintf(procfile, len + 1, fmt, pid);

    /* Loops on lines
     * Format:
     * 08134000-0813a000 rw-p 000eb000 fe:00 868355     /bin/bash
     * 0813a000-0813f000 rw-p 00000000 00:00 0
     * b7721000-b7740000 r-xp 00000000 fe:00 901950     /lib/ld-2.18.so
     * bfe44000-bfe65000 rw-p 00000000 00:00 0          [stack]
     */

#ifdef DEBUG
    fprintf(stderr, "Parsing %s\n", procfile);
#endif
    fp = fopen(procfile, "r");

    while((line = read_line(line, &length, fp)) != NULL)
    {
        unsigned long int addr_start, addr_end;
        char perms[5];
        unsigned long int offset;
        unsigned int dev_major, dev_minor;
        unsigned long int inode;
        char pathname[4096];
        sscanf(line,
               "%lx-%lx %4s %lx %x:%x %lu %s",
               &addr_start, &addr_end,
               perms,
               &offset,
               &dev_major, &dev_minor,
               &inode,
               pathname);

#ifdef DEBUG
        fprintf(stderr,
                "proc line:\n"
                "    addr_start: %lx\n"
                "    addr_end: %lx\n"
                "    perms: %s\n"
                "    offset: %lx\n"
                "    dev_major: %x\n"
                "    dev_minor: %x\n"
                "    inode: %lu\n"
                "    pathname: %s\n",
                addr_start, addr_end,
                perms,
                offset,
                dev_major, dev_minor,
                inode,
                pathname);
#endif
        if(inode > 0)
        {
            if(strncmp(pathname, binary, 4096) != 0
             && strncmp(previous_path, pathname, 4096) != 0)
            {
#ifdef DEBUG
                fprintf(stderr, "    adding to database\n");
#endif
                if(db_add_file_open(process, pathname, FILE_READ) != 0)
                    return -1;
                strncpy(previous_path, pathname, 4096);
            }
        }
    }
    return 0;
}

char *trace_unhandled_syscall(int syscall, struct Process *process)
{
    const char *name = NULL;
    int type = 0;
    switch(syscall)
    {
    /* Path as first argument */
    case SYS_mkdir:
        name = "mkdir";
        break;
    case SYS_rename:
        name = "rename";
        break;
    case SYS_rmdir:
        name = "rmdir";
        break;
    case SYS_link:
        name = "link";
        break;
    case SYS_truncate:
#ifdef SYS_truncate64
    case SYS_truncate64: /* added for big file support on x86 */
#endif
        name = "truncate";
        break;
    case SYS_unlink:
        name = "unlink";
        break;
    case SYS_chmod:
        name = "chmod";
        break;
    case SYS_chown:
#ifdef SYS_chown32
    case SYS_chown32: /* added for 32-bit ids on x86 */
#endif
        name = "chown";
        break;
    case SYS_lchown:
#ifdef SYS_lchown32
    case SYS_lchown32: /* added for 32-bit ids on x86 */
#endif
        name = "lchown";
        break;
    case SYS_utime:
        name = "utime";
        break;
    case SYS_utimes:
        name = "utimes";
        break;

    /* Path as second argument */
    case SYS_symlink:
        name = "symlink"; type = 1;
        break;

    /* Functions that use open descriptors, which we currently don't track */
    case SYS_linkat:
        name = "linkat"; type = 2;
        break;
    case SYS_mkdirat:
        name = "mkdirat"; type = 2;
        break;
    case SYS_openat:
        name = "openat"; type = 2;
        break;
    case SYS_renameat:
        name = "renameat"; type = 2;
        break;
    case SYS_symlinkat:
        name = "symlinkat"; type = 2;
        break;
    case SYS_unlinkat:
        name = "unlinkat"; type = 2;
        break;
    case SYS_fchmodat:
        name = "fchmodat"; type = 2;
        break;
    case SYS_fchownat:
        name = "fchownat"; type = 2;
        break;
    case SYS_readlinkat:
        name = "readlinkat"; type = 2;
        break;
    }

    if(name == NULL)
        return NULL;
    else if(type == 0 || type == 1)
    {
        char *pathname = tracee_strdup(process->pid,
                                       (void*)process->params[type]);
        if(pathname[0] != '/')
        {
            char *oldpath = pathname;
            pathname = abspath(process->wd, oldpath);
            free(oldpath);
        }
        {
            const char *fmt = "%s(\"%s\")";
            char dummy;
            int len = snprintf(&dummy, 1, fmt, name, pathname);
            char *s = malloc(len + 1);
            snprintf(s, len + 1, fmt, name, pathname);
            free(pathname);
            return s;
        }
    }
    else /* type == 2 */
        return strdup(name);
}

int trace_handle_syscall(struct Process *process)
{
    pid_t pid = process->pid;
    const int syscall = process->current_syscall;
#ifdef DEBUG
    if(syscall == SYS_open || syscall == SYS_execve || syscall == SYS_fork
     || syscall == SYS_vfork || syscall == SYS_clone)
    {
        const char *callname = (syscall == SYS_open)?"open":
                               (syscall == SYS_execve)?"execve":
                               (syscall == SYS_fork)?"fork":
                               (syscall == SYS_vfork)?"vfork":
                               "clone";
        fprintf(stderr, "syscall=%u %s, in_syscall=%u\n",
                syscall, callname, process->in_syscall);
    }
#endif
    /* ********************
     * open(), creat(), access()
     */
    if(process->in_syscall && (syscall == SYS_open || syscall == SYS_creat
        || syscall == SYS_access) )
    {
        unsigned int mode;
        char *pathname = tracee_strdup(pid, (void*)process->params[0]);
        if(pathname[0] != '/')
        {
            char *oldpath = pathname;
            pathname = abspath(process->wd, oldpath);
            free(oldpath);
        }
#ifdef DEBUG
        fprintf(stderr, "%s(\"%s\") = %d (%s)\n",
                (syscall == SYS_open)?"open":
                    (syscall == SYS_creat)?"creat":"access",
                pathname,
                (int)process->retvalue,
                (process->retvalue >= 0)?"success":"failure");
#endif
        if(process->retvalue >= 0)
        {
            if(syscall == SYS_access)
                mode = FILE_STAT;
            else if(syscall == SYS_creat)
                mode = flags2mode(process->params[1] |
                                  O_CREAT | O_WRONLY | O_TRUNC);
            else /* syscall == SYS_open */
                mode = flags2mode(process->params[1]);

            if(db_add_file_open(process->identifier,
                                pathname,
                                mode) != 0)
                return -1;
        }
        free(pathname);
    }
    /* ********************
     * stat(), lstat()
     */
    else if(process->in_syscall
          && (syscall == SYS_stat || syscall == SYS_lstat
#ifdef SYS_stat64
             || syscall == SYS_stat64
#endif
#ifdef SYS_oldstat
             || syscall == SYS_oldstat
#endif
#ifdef SYS_lstat64
             || syscall == SYS_lstat64
#endif
#ifdef SYS_oldlstat
             || syscall == SYS_oldlstat
#endif
              ) )
    {
        char *pathname = tracee_strdup(pid, (void*)process->params[0]);
        if(pathname[0] != '/')
        {
            char *oldpath = pathname;
            pathname = abspath(process->wd, oldpath);
            free(oldpath);
        }
#ifdef DEBUG
        fprintf(stderr, "%s(\"%s\") = %d (%s)\n",
                (syscall == SYS_stat
#ifdef SYS_stat64
               || syscall == SYS_stat64
#endif
#ifdef SYS_oldstat
               || syscall == SYS_oldstat
#endif
                 )?"stat":"lstat",
                pathname,
                (int)process->retvalue,
                (process->retvalue >= 0)?"success":"failure");
#endif
        if(process->retvalue >= 0)
        {
            if(db_add_file_open(process->identifier,
                                pathname,
                                FILE_STAT) != 0)
                return -1;
        }
        free(pathname);
    }
    /* ********************
     * readlink()
     */
    else if(process->in_syscall && syscall == SYS_readlink)
    {
        char *pathname = tracee_strdup(pid, (void*)process->params[0]);
        if(pathname[0] != '/')
        {
            char *oldpath = pathname;
            pathname = abspath(process->wd, oldpath);
            free(oldpath);
        }
#ifdef DEBUG
        fprintf(stderr, "readlink(\"%s\") = %d (%s)\n",
                pathname,
                (int)process->retvalue,
                (process->retvalue >= 0)?"success":"failure");
#endif
        if(process->retvalue >= 0)
        {
            if(db_add_file_open(process->identifier,
                                pathname,
                                FILE_STAT) != 0)
                return -1;
        }
        free(pathname);
    }
    /* ********************
     * chdir()
     */
    else if(process->in_syscall && syscall == SYS_chdir)
    {
        char *pathname = tracee_strdup(pid, (void*)process->params[0]);
        if(pathname[0] != '/')
        {
            char *oldpath = pathname;
            pathname = abspath(process->wd, oldpath);
            free(oldpath);
        }
#ifdef DEBUG
        fprintf(stderr, "chdir(\"%s\") = %d (%s)\n", pathname,
                (int)process->retvalue,
                (process->retvalue >= 0)?"success":"failure");
#endif
        if(process->retvalue >= 0)
        {
            free(process->wd);
            process->wd = pathname;
            if(db_add_file_open(process->identifier,
                                pathname,
                                FILE_WDIR) != 0)
                return -1;
        }
        else
            free(pathname);
    }
    /* ********************
     * execve()
     */
    else if(!process->in_syscall && syscall == SYS_execve)
    {
        /* int execve(const char *filename,
         *            char *const argv[],
         *            char *const envp[]); */
        struct ExecveInfo *execi = malloc(sizeof(struct ExecveInfo));
#ifdef DEBUG
        fprintf(stderr, "Entering execve, getting arguments...\n");
#endif
        execi->binary = tracee_strdup(pid, (void*)process->params[0]);
        if(execi->binary[0] != '/')
        {
            char *oldbin = execi->binary;
            execi->binary = abspath(process->wd, oldbin);
            free(oldbin);
        }
        execi->argv = tracee_strarraydup(pid, (void*)process->params[1]);
        execi->envp = tracee_strarraydup(pid, (void*)process->params[2]);
#ifdef DEBUG
        fprintf(stderr, "Got arguments:\n  binary=%s\n  argv:\n",
                execi->binary);
        {
            /* Note: this conversion is correct and shouldn't need a cast */
            const char *const *v = (const char* const*)execi->argv;
            while(*v)
            {
                fprintf(stderr, "    %s\n", *v);
                ++v;
            }
        }
        {
            /* Note: this conversion is correct and shouldn't need a cast */
            size_t nb = 0;
            while(execi->envp[nb] != NULL)
                ++nb;
            fprintf(stderr, "  envp: (%u entries)\n", (unsigned int)nb);
        }
#endif
        process->syscall_info = execi;
    }
    else if(process->in_syscall && syscall == SYS_execve)
    {
        struct ExecveInfo *execi = process->syscall_info;
        if(process->retvalue >= 0)
        {
            /* Note: exec->argv needs cast to suppress a bogus GCC warning
             * While conversion from char** to const char** is invalid,
             * conversion from char** to const char*const* is, in fact, safe.
             * G++ accepts it, GCC issues a warning */
            if(db_add_exec(process->identifier, execi->binary,
                           (const char *const*)execi->argv,
                           (const char *const*)execi->envp) != 0)
                return -1;
#ifdef DEBUG
            fprintf(stderr, "Proc %d successfully exec'd %s\n",
                    process->pid, execi->binary);
#endif
            if(trace_add_files_from_proc(process->identifier, process->pid,
                                         execi->binary) != 0)
                return -1;
        }

        free_strarray(execi->argv);
        free_strarray(execi->envp);
        free(execi->binary);
        free(execi);
    }
    /* ********************
     * fork(), clone(), ...
     */
    else if(process->in_syscall
          && (syscall == SYS_fork || syscall == SYS_vfork
            || syscall == SYS_clone) )
    {
        if(process->retvalue > 0)
        {
            pid_t new_pid = process->retvalue;
            struct Process *new_process;
#ifdef DEBUG
            fprintf(stderr, "Process %d created by %d via %s\n",
                    new_pid, process->pid,
                    (syscall == SYS_fork)?"fork()":
                    (syscall == SYS_vfork)?"vfork()":
                    "clone()");
#endif
            new_process = trace_get_empty_process();
            new_process->status = PROCESS_ALLOCATED;
            new_process->pid = new_pid;
            new_process->in_syscall = 0;
            new_process->wd = strdup(process->wd);
#ifdef DEBUG
            fprintf(stderr, "WD = \"%s\"\n", new_process->wd);
#endif
            if(db_add_process(&new_process->identifier,
                              process->identifier,
                              process->wd) != 0)
                return -1;
        }
    }
    /* ********************
     * Other syscalls that might be of interest but that we don't handle yet
     */
    else if(process->in_syscall && process->retvalue >= 0)
    {
        char *desc = trace_unhandled_syscall(syscall, process);
        if(desc != NULL)
        {
            fprintf(stderr,
                    "WARNING: process %d used unhandled system call %s\n",
                    process->pid, desc);
            free(desc);
        }
    }

    /* Run to next syscall */
    if(process->in_syscall)
    {
        process->in_syscall = 0;
        process->current_syscall = -1;
        process->syscall_info = NULL;
    }
    else
        process->in_syscall = 1;
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

    return 0;
}

int trace(pid_t first_proc, int *first_exit_code)
{
    int nprocs = 0;
    for(;;)
    {
        int status;
        pid_t pid;
        struct Process *process;

        /* Wait for a process */
        pid = waitpid(-1, &status, __WALL);
        if(WIFEXITED(status))
        {
            fprintf(stderr, "Process %d exited, %d processes remain\n",
                    pid, nprocs-1);
            if(pid == first_proc && first_exit_code != NULL)
            {
                if(WIFSIGNALED(status))
                    /* exit codes are 8 bits */
                    *first_exit_code = 0x0100 | WTERMSIG(status);
                else
                    *first_exit_code = WEXITSTATUS(status);
            }
            process = trace_find_process(pid);
            if(process != NULL)
            {
                free(process->wd);
                process->status = PROCESS_FREE;
            }
            --nprocs;
            if(nprocs <= 0)
                break;
            continue;
        }

        process = trace_find_process(pid);
        if(process == NULL)
        {
            fprintf(stderr, "Warning: found unexpected process %d\n", pid);
            process = trace_get_empty_process();
            process->status = PROCESS_ALLOCATED;
            process->pid = pid;
            process->in_syscall = 0;
            process->wd = get_p_wd(pid);
            if(db_add_first_process(&process->identifier, process->wd) != 0)
                return -1;
        }
        if(process->status != PROCESS_ATTACHED)
        {
#ifdef DEBUG
            fprintf(stderr, "Allocating Process for %d\n", pid);
#endif
            process->status = PROCESS_ATTACHED;

            fprintf(stderr, "Process %d attached\n", pid);
            ++nprocs;
            ptrace(PTRACE_SETOPTIONS, pid, 0,
                   PTRACE_O_TRACESYSGOOD |  /* Adds 0x80 bit to SIGTRAP signals
                                             * if paused because of syscall */
                   PTRACE_O_TRACECLONE |
                   PTRACE_O_TRACEFORK |
                   PTRACE_O_TRACEVFORK);
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            continue;
        }

#ifdef DEBUG
        if(!WIFSTOPPED(status))
            fprintf(stderr, "Process %d is NOT stopped\n", pid);
        else if( (WSTOPSIG(status) & 0x80) == 0)
            fprintf(stderr, "Process %d is NOT stopped because of syscall "
                    "(WSTOPSIG=%u)\n", pid, WSTOPSIG(status));
#endif

        if(WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
        {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
#if defined(I386)
            process->current_syscall = regs.orig_eax;
            if(process->in_syscall)
                process->retvalue = regs.eax;
            else
            {
                process->params[0] = regs.ebx;
                process->params[1] = regs.ecx;
                process->params[2] = regs.edx;
                process->params[3] = regs.esi;
                process->params[4] = regs.edi;
                process->params[5] = regs.ebp;
            }
#elif defined(X86_64)
            process->current_syscall = regs.orig_rax;
            if(process->in_syscall)
                process->retvalue = regs.rax;
            else
            {
                process->params[0] = regs.rdi;
                process->params[1] = regs.rsi;
                process->params[2] = regs.rdx;
                process->params[3] = regs.r10;
                process->params[4] = regs.r8;
                process->params[5] = regs.r9;
            }
#endif
            if(trace_handle_syscall(process) != 0)
                return -1;
        }
        /* Continue on SIGTRAP */
        else if(WIFSTOPPED(status))
        {
#ifdef DEBUG
            fprintf(stderr, "Resuming %d on signal\n", pid);
#endif
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        }
    }

    return 0;
}

void cleanup(void)
{
    size_t i;
#ifdef DEBUG
    {
        size_t nb = 0;
        for(i = 0; i < processes_size; ++i)
            if(processes[i]->status != PROCESS_FREE)
                ++nb;
        /* size_t size is implementation dependent; %u for size_t can trigger
         * a warning */
        fprintf(stderr, "Cleaning up, %u processes to kill...\n",
                (unsigned int)nb);
    }
#endif
    for(i = 0; i < processes_size; ++i)
    {
        if(processes[i]->status != PROCESS_FREE)
        {
            kill(processes[i]->pid, SIGKILL);
            free(processes[i]->wd);
        }
    }
}

void sigint_handler(int signo)
{
    (void)signo;
    cleanup();
    exit(1);
}

void trace_init(void)
{
    signal(SIGCHLD, SIG_DFL);
    signal(SIGINT, sigint_handler);

    if(processes == NULL)
    {
        size_t i;
        struct Process *pool;
        processes_size = 16;
        processes = malloc(processes_size * sizeof(*processes));
        pool = malloc(processes_size * sizeof(*pool));
        for(i = 0; i < processes_size; ++i)
        {
            processes[i] = pool++;
            processes[i]->status = PROCESS_FREE;
            processes[i]->in_syscall = 0;
            processes[i]->current_syscall = -1;
            processes[i]->syscall_info = NULL;
            processes[i]->wd = NULL;
        }
    }
}

int fork_and_trace(const char *binary, int argc, char **argv,
                   const char *database_path, int *exit_status)
{
    pid_t child;

    trace_init();

    child = fork();

#ifdef DEBUG
    if(child != 0)
        fprintf(stderr, "Child created, pid=%d\n", child);
#endif

    if(child == 0)
    {
        char **args = malloc((argc + 1) * sizeof(char*));
        memcpy(args, argv, argc * sizeof(char*));
        args[argc] = NULL;
        /* Trace this process */
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        /* Stop this once so tracer can set options */
        kill(getpid(), SIGSTOP);
        /* Execute the target */
        execvp(binary, args);
        perror("Couldn't execute the target command (execvp returned)");
        return 1;
    }

    if(db_init(database_path) != 0)
    {
        kill(child, SIGKILL);
        return 1;
    }

    /* Creates entry for first process */
    {
        struct Process *process = trace_get_empty_process();
        process->status = PROCESS_ALLOCATED; /* Not yet attached... */
        process->pid = child;
        process->in_syscall = 0;
        process->wd = get_wd();

        fprintf(stderr, "Process %d created by initial fork()\n", child);
#ifdef DEBUG
        fprintf(stderr, "WD = \"%s\"\n", process->wd);
#endif
        if(db_add_first_process(&process->identifier, process->wd) != 0)
        {
            cleanup();
            return 1;
        }
    }

    if(trace(child, exit_status) != 0)
    {
        cleanup();
        db_close();
        return 1;
    }

    if(db_close() != 0)
        return 1;

    return 0;
}
