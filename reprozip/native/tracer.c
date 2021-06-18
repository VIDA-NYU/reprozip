#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "database.h"
#include "log.h"
#include "ptrace_utils.h"
#include "syscalls.h"
#include "tracer.h"
#include "utils.h"


#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif


struct i386_regs {
    int32_t ebx;
    int32_t ecx;
    int32_t edx;
    int32_t esi;
    int32_t edi;
    int32_t ebp;
    int32_t eax;
    int32_t xds;
    int32_t xes;
    int32_t xfs;
    int32_t xgs;
    int32_t orig_eax;
    int32_t eip;
    int32_t xcs;
    int32_t eflags;
    int32_t esp;
    int32_t xss;
};


struct x86_64_regs {
    int64_t r15;
    int64_t r14;
    int64_t r13;
    int64_t r12;
    int64_t rbp;
    int64_t rbx;
    int64_t r11;
    int64_t r10;
    int64_t r9;
    int64_t r8;
    int64_t rax;
    int64_t rcx;
    int64_t rdx;
    int64_t rsi;
    int64_t rdi;
    int64_t orig_rax;
    int64_t rip;
    int64_t cs;
    int64_t eflags;
    int64_t rsp;
    int64_t ss;
    int64_t fs_base;
    int64_t gs_base;
    int64_t ds;
    int64_t es;
    int64_t fs;
    int64_t gs;
};


static void get_i386_reg(register_type *reg, uint32_t value)
{
    reg->i = (int32_t)value;
    reg->u = value;
    reg->p = (void*)(uint64_t)value;
}

static void get_x86_64_reg(register_type *reg, uint64_t value)
{
    reg->i = (int64_t)value;
    reg->u = value;
    reg->p = (void*)value;
}


void free_execve_info(struct ExecveInfo *execi)
{
    free_strarray(execi->argv);
    free_strarray(execi->envp);
    free(execi->binary);
    free(execi);
}


struct Process **processes = NULL;
size_t processes_size;

struct Process *trace_find_process(pid_t tid)
{
    size_t i;
    for(i = 0; i < processes_size; ++i)
    {
        if(processes[i]->status != PROCSTAT_FREE && processes[i]->tid == tid)
            return processes[i];
    }
    return NULL;
}

struct Process *trace_get_empty_process(void)
{
    size_t i;
    for(i = 0; i < processes_size; ++i)
    {
        if(processes[i]->status == PROCSTAT_FREE)
            return processes[i];
    }

    /* Count unknown processes */
    if(logging_level <= 10)
    {
        size_t unknown = 0;
        for(i = 0; i < processes_size; ++i)
            if(processes[i]->status == PROCSTAT_UNKNOWN)
                ++unknown;
        log_debug(0, "there are %u/%u UNKNOWN processes",
                  (unsigned int)unknown, (unsigned int)processes_size);
    }

    /* Allocate more! */
    log_debug(0, "process table full (%d), reallocating",
              (int)processes_size);
    {
        struct Process *pool;
        size_t prev_size = processes_size;
        processes_size *= 2;
        pool = malloc((processes_size - prev_size) * sizeof(*pool));
        processes = realloc(processes, processes_size * sizeof(*processes));
        for(; i < processes_size; ++i)
        {
            processes[i] = pool++;
            processes[i]->status = PROCSTAT_FREE;
            processes[i]->threadgroup = NULL;
            processes[i]->execve_info = NULL;
        }
        return processes[prev_size];
    }
}

struct ThreadGroup *trace_new_threadgroup(pid_t tgid, char *wd)
{
    struct ThreadGroup *threadgroup = malloc(sizeof(struct ThreadGroup));
    threadgroup->tgid = tgid;
    threadgroup->wd = wd;
    threadgroup->refs = 1;
    log_debug(tgid, "threadgroup (= process) created");
    return threadgroup;
}

void trace_free_process(struct Process *process)
{
    process->status = PROCSTAT_FREE;
    if(process->threadgroup != NULL)
    {
        process->threadgroup->refs--;
        log_debug(process->tid,
                  "process died, threadgroup tgid=%d refs=%d",
                  process->threadgroup->tgid, process->threadgroup->refs);
        if(process->threadgroup->refs == 0)
        {
            log_debug(process->threadgroup->tgid,
                      "deallocating threadgroup");
            if(process->threadgroup->wd != NULL)
                free(process->threadgroup->wd);
            free(process->threadgroup);
        }
        process->threadgroup = NULL;
    }
    else
        log_debug(process->tid, "threadgroup==NULL"); /* LCOV_EXCL_LINE */
    if(process->execve_info != NULL)
    {
        free_execve_info(process->execve_info);
        process->execve_info = NULL;
    }
}

void trace_count_processes(unsigned int *p_nproc, unsigned int *p_unknown)
{
    unsigned int nproc = 0, unknown = 0;
    size_t i;
    for(i = 0; i < processes_size; ++i)
    {
        switch(processes[i]->status)
        {
        case PROCSTAT_FREE:
            break;
        case PROCSTAT_UNKNOWN:
            /* Exists but no corresponding syscall has returned yet */
            ++unknown;
            ++nproc;
            break;
        case PROCSTAT_ALLOCATED:
            /* Not yet attached but it will show up eventually */
        case PROCSTAT_ATTACHED:
            /* Running */
            ++nproc;
            break;
        }
    }
    if(p_nproc != NULL)
        *p_nproc = nproc;
    if(p_unknown != NULL)
        *p_unknown = unknown;
}

int trace_add_files_from_proc(unsigned int process, pid_t tid,
                              const char *binary)
{
    FILE *fp;
    char dummy;
    char *line = NULL;
    size_t length = 0;
    char previous_path[4096] = "";

    const char *const fmt = "/proc/%d/maps";
    int len = snprintf(&dummy, 1, fmt, tid);
    char *procfile = malloc(len + 1);
    snprintf(procfile, len + 1, fmt, tid);

    /* Loops on lines
     * Format:
     * 08134000-0813a000 rw-p 000eb000 fe:00 868355     /bin/bash
     * 0813a000-0813f000 rw-p 00000000 00:00 0
     * b7721000-b7740000 r-xp 00000000 fe:00 901950     /lib/ld-2.18.so
     * bfe44000-bfe65000 rw-p 00000000 00:00 0          [stack]
     */

#ifdef DEBUG_PROC_PARSER
    log_info(tid, "parsing %s", procfile);
#endif
    fp = fopen(procfile, "r");
    free(procfile);

    while((line = read_line(line, &length, fp)) != NULL)
    {
        unsigned long int addr_start, addr_end;
        char perms[5];
        unsigned long int offset;
        unsigned int dev_major, dev_minor;
        unsigned long int inode;
        int path_offset;
        int ret = sscanf(line,
               "%lx-%lx %4s %lx %x:%x %lu %n",
               &addr_start, &addr_end,
               perms,
               &offset,
               &dev_major, &dev_minor,
               &inode,
               &path_offset);
        char *pathname = line + path_offset;
        if(ret != 7)
        {
            /* LCOV_EXCL_START : Broken or unexpected proc file format*/
            log_error(tid, "Invalid format in /proc/%d/maps (%d):\n  %s", tid,
                      ret, line);
            free(line);
            fclose(fp);
            return -1;
            /* LCOV_EXCL_STOP */
        }

#ifdef DEBUG_PROC_PARSER
        log_info(tid,
                 "proc line:\n"
                 "    addr_start: %lx\n"
                 "    addr_end: %lx\n"
                 "    perms: %s\n"
                 "    offset: %lx\n"
                 "    dev_major: %x\n"
                 "    dev_minor: %x\n"
                 "    inode: %lu\n"
                 "    pathname: %s",
                 addr_start, addr_end,
                 perms,
                 offset,
                 dev_major, dev_minor,
                 inode,
                 pathname);
#endif
        if(inode > 0)
        {
            if(strcmp(pathname, binary) != 0
             && strncmp(pathname, previous_path, 4096) != 0)
            {
#ifdef DEBUG_PROC_PARSER
                log_info(tid, "    adding to database");
#endif
                if(db_add_file_open(process, pathname,
                                    FILE_READ, path_is_dir(pathname)) != 0)
                    return -1;
                strncpy(previous_path, pathname, 4096);
            }
        }
    }
    fclose(fp);
    return 0;
}

static void trace_set_options(pid_t tid)
{
    ptrace(PTRACE_SETOPTIONS, tid, 0,
           PTRACE_O_TRACESYSGOOD |  /* Adds 0x80 bit to SIGTRAP signals
                                     * if paused because of syscall */
#ifdef PTRACE_O_EXITKILL
           PTRACE_O_EXITKILL |
#endif
           PTRACE_O_TRACECLONE |
           PTRACE_O_TRACEFORK |
           PTRACE_O_TRACEVFORK |
           PTRACE_O_TRACEEXEC);
}

static int trace(pid_t first_proc, int *first_exit_code)
{
    for(;;)
    {
        int status;
        pid_t tid;
        struct Process *process;

        /* Wait for a process */
        tid = waitpid(-1, &status, __WALL);
        if(tid == -1)
        {
            /* LCOV_EXCL_START : internal error: waitpid() won't fail unless we
             * mistakingly call it while there is no child to wait for */
            log_critical(0, "waitpid failed: %s", strerror(errno));
            return -1;
            /* LCOV_EXCL_STOP */
        }
        if(WIFEXITED(status) || WIFSIGNALED(status))
        {
            unsigned int nprocs, unknown;
            int exitcode;
            if(WIFSIGNALED(status))
                /* exit codes are 8 bits */
                exitcode = 0x0100 | WTERMSIG(status);
            else
                exitcode = WEXITSTATUS(status);

            if(tid == first_proc && first_exit_code != NULL)
                *first_exit_code = exitcode;
            process = trace_find_process(tid);
            if(process != NULL)
            {
                if(db_add_exit(process->identifier, exitcode) != 0)
                    return -1; /* LCOV_EXCL_LINE */
                trace_free_process(process);
            }
            trace_count_processes(&nprocs, &unknown);
            log_info(tid, "process exited (%s %d), %d processes remain",
                     (exitcode & 0x0100)?"signal":"code", exitcode & 0xFF,
                     (unsigned int)nprocs);
            if(nprocs <= 0)
                break;
            if(unknown >= nprocs)
            {
                /* LCOV_EXCL_START : This can't happen because UNKNOWN
                 * processes are the forked processes whose creator has not
                 * returned yet. Therefore, if there is an UNKNOWN process, its
                 * creator has to exist as well (and it is not UNKNOWN). */
                log_critical(0, "only UNKNOWN processes remaining (%d)",
                             (unsigned int)nprocs);
                return -1;
                /* LCOV_EXCL_STOP */
            }
            continue;
        }

        process = trace_find_process(tid);
        if(process == NULL)
        {
            log_debug(tid, "process appeared");
            process = trace_get_empty_process();
            process->status = PROCSTAT_UNKNOWN;
            process->flags = 0;
            process->tid = tid;
            process->threadgroup = NULL;
            process->in_syscall = 0;
            trace_set_options(tid);
            /* Don't resume, it will be set to ATTACHED and resumed when fork()
             * returns */
            continue;
        }
        else if(process->status == PROCSTAT_ALLOCATED)
        {
            process->status = PROCSTAT_ATTACHED;

            log_debug(tid, "process attached");
            trace_set_options(tid);
            ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
            if(logging_level <= 20)
            {
                unsigned int nproc, unknown;
                trace_count_processes(&nproc, &unknown);
                log_info(0, "%d processes (inc. %d unattached)",
                         nproc, unknown);
            }
            continue;
        }

        if(WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
        {
            size_t len = 0;
#ifdef I386
            struct i386_regs regs;
#else /* def X86_64 */
            struct x86_64_regs regs;
#endif
            /* Try to use GETREGSET first, since iov_len allows us to know if
             * 32bit or 64bit mode was used */
#ifdef PTRACE_GETREGSET
#ifndef NT_PRSTATUS
#define NT_PRSTATUS  1
#endif
            {
                struct iovec iov;
                iov.iov_base = &regs;
                iov.iov_len = sizeof(regs);
                if(ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov) == 0)
                    len = iov.iov_len;
            }
            if(len == 0)
#endif
            /* GETREGSET undefined or call failed, fallback on GETREGS */
            {
                /* LCOV_EXCL_START : GETREGSET was added by Linux 2.6.34 in
                 * May 2010 (2225a122) */
                ptrace(PTRACE_GETREGS, tid, NULL, &regs);
                /* LCOV_EXCL_STOP */
            }
#if defined(I386)
            if(!process->in_syscall)
                process->current_syscall = regs.orig_eax;
            if(process->in_syscall)
                get_i386_reg(&process->retvalue, regs.eax);
            else
            {
                get_i386_reg(&process->params[0], regs.ebx);
                get_i386_reg(&process->params[1], regs.ecx);
                get_i386_reg(&process->params[2], regs.edx);
                get_i386_reg(&process->params[3], regs.esi);
                get_i386_reg(&process->params[4], regs.edi);
                get_i386_reg(&process->params[5], regs.ebp);
            }
            process->mode = MODE_I386;
#elif defined(X86_64)
            /* On x86_64, process might be 32 or 64 bits */
            /* If len is known (not 0) and not that of x86_64 registers,
             * or if len is not known (0) and CS is 0x23 (not as reliable) */
            if( (len != 0 && len != sizeof(regs))
             || (len == 0 && regs.cs == 0x23) )
            {
                /* 32 bit mode */
                struct i386_regs *x86regs = (struct i386_regs*)&regs;
                if(!process->in_syscall)
                    process->current_syscall = x86regs->orig_eax;
                if(process->in_syscall)
                    get_i386_reg(&process->retvalue, x86regs->eax);
                else
                {
                    get_i386_reg(&process->params[0], x86regs->ebx);
                    get_i386_reg(&process->params[1], x86regs->ecx);
                    get_i386_reg(&process->params[2], x86regs->edx);
                    get_i386_reg(&process->params[3], x86regs->esi);
                    get_i386_reg(&process->params[4], x86regs->edi);
                    get_i386_reg(&process->params[5], x86regs->ebp);
                }
                process->mode = MODE_I386;
            }
            else
            {
                /* 64 bit mode */
                if(!process->in_syscall)
                    process->current_syscall = regs.orig_rax;
                if(process->in_syscall)
                    get_x86_64_reg(&process->retvalue, regs.rax);
                else
                {
                    get_x86_64_reg(&process->params[0], regs.rdi);
                    get_x86_64_reg(&process->params[1], regs.rsi);
                    get_x86_64_reg(&process->params[2], regs.rdx);
                    get_x86_64_reg(&process->params[3], regs.r10);
                    get_x86_64_reg(&process->params[4], regs.r8);
                    get_x86_64_reg(&process->params[5], regs.r9);
                }
                /* Might still be either native x64 or Linux's x32 layer */
                process->mode = MODE_X86_64;
            }
#endif
            if(syscall_handle(process) != 0)
                return -1; /* LCOV_EXCL_LINE */
        }
        /* Handle signals */
        else if(WIFSTOPPED(status))
        {
            int signum = WSTOPSIG(status) & 0x7F;

            /* Synthetic signal for ptrace event: resume */
            if(signum == SIGTRAP && status & 0xFF0000)
            {
                int event = status >> 16;
                if(event == PTRACE_EVENT_EXEC)
                {
                    log_debug(tid,
                             "got EVENT_EXEC, an execve() was successful and "
                             "will return soon");
                    if(syscall_execve_event(process) != 0)
                        return -1;
                }
                else if( (event == PTRACE_EVENT_FORK)
                      || (event == PTRACE_EVENT_VFORK)
                      || (event == PTRACE_EVENT_CLONE))
                {
                    if(syscall_fork_event(process, event) != 0)
                        return -1;
                }
                ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
            }
            else if(signum == SIGTRAP)
            {
                /* LCOV_EXCL_START : Processes shouldn't be getting SIGTRAPs */
                log_error(0,
                          "NOT delivering SIGTRAP to %d\n"
                          "    waitstatus=0x%X", tid, status);
                ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
                /* LCOV_EXCL_STOP */
            }
            /* Other signal, let the process handle it */
            else
            {
                siginfo_t si;
                log_info(tid, "caught signal %d", signum);
                if(ptrace(PTRACE_GETSIGINFO, tid, 0, (long)&si) >= 0)
                    ptrace(PTRACE_SYSCALL, tid, NULL, signum);
                else
                {
                    /* LCOV_EXCL_START : Not sure what this is for... doesn't
                     * seem to happen in practice */
                    log_error(tid, "    NOT delivering: %s", strerror(errno));
                    if(signum != SIGSTOP)
                        ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
                    /* LCOV_EXCL_STOP */
                }
            }
        }
    }

    return 0;
}

static void (*python_sigchld_handler)(int) = NULL;
static void (*python_sigint_handler)(int) = NULL;

static void restore_signals(void)
{
    if(python_sigchld_handler != NULL)
    {
        signal(SIGCHLD, python_sigchld_handler);
        python_sigchld_handler = NULL;
    }
    if(python_sigint_handler != NULL)
    {
        signal(SIGINT, python_sigint_handler);
        python_sigint_handler = NULL;
    }
}

static void cleanup(void)
{
    size_t i;
    {
        size_t nb = 0;
        for(i = 0; i < processes_size; ++i)
            if(processes[i]->status != PROCSTAT_FREE)
                ++nb;
        /* size_t size is implementation dependent; %u for size_t can trigger
         * a warning */
        log_error(0, "cleaning up, %u processes to kill...", (unsigned int)nb);
    }
    for(i = 0; i < processes_size; ++i)
    {
        if(processes[i]->status != PROCSTAT_FREE)
        {
            kill(processes[i]->tid, SIGKILL);
            trace_free_process(processes[i]);
        }
    }
}

static time_t last_int = 0;

static void sigint_handler(int signo)
{
    time_t now = time(NULL);
    (void)signo;
    if(now - last_int < 2)
    {
        log_error(0, "cleaning up on SIGINT");
        cleanup();
        restore_signals();
        exit(128 + 2);
    }
    else
        log_error(0, "Got SIGINT, press twice to abort...");
    last_int = now;
}

static void trace_init(void)
{
    /* Store Python's handlers for restore_signals() */
    python_sigchld_handler = signal(SIGCHLD, SIG_DFL);
    python_sigint_handler = signal(SIGINT, sigint_handler);

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
            processes[i]->status = PROCSTAT_FREE;
            processes[i]->threadgroup = NULL;
            processes[i]->execve_info = NULL;
        }
    }

    syscall_build_table();
}

int fork_and_trace(const char *binary, int argc, char **argv,
                   const char *database_path, int *exit_status)
{
    pid_t child;

    trace_init();

    child = fork();

    if(child != 0)
        log_info(0, "child created, pid=%d", child);

    if(child == 0)
    {
        char **args = malloc((argc + 1) * sizeof(char*));
        memcpy(args, argv, argc * sizeof(char*));
        args[argc] = NULL;
        /* Trace this process */
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0)
        {
            log_critical(
                0,
                "couldn't use ptrace: %s\n"
                "This could be caused by a security policy or isolation "
                "mechanism (such as Docker), see http://bit.ly/2bZd8Fa",
                strerror(errno));
            exit(125);
        }
        /* Stop this once so tracer can set options */
        kill(getpid(), SIGSTOP);
        /* Execute the target */
        execvp(binary, args);
        log_critical(0, "couldn't execute the target command (execvp "
                     "returned): %s", strerror(errno));
        exit(127);
    }

    if(db_init(database_path) != 0)
    {
        kill(child, SIGKILL);
        restore_signals();
        return 1;
    }

    /* Creates entry for first process */
    {
        struct Process *process = trace_get_empty_process();
        process->status = PROCSTAT_ALLOCATED; /* Not yet attached... */
        process->flags = 0;
        /* We sent a SIGSTOP, but we resume on attach */
        process->tid = child;
        process->threadgroup = trace_new_threadgroup(child, get_wd());
        process->in_syscall = 0;

        log_info(0, "process %d created by initial fork()", child);
        if( (db_add_first_process(&process->identifier,
                                  process->threadgroup->wd) != 0)
         || (db_add_file_open(process->identifier, process->threadgroup->wd,
                              FILE_WDIR, 1) != 0) )
        {
            /* LCOV_EXCL_START : Database insertion shouldn't fail */
            db_close(1);
            cleanup();
            restore_signals();
            return 1;
            /* LCOV_EXCL_STOP */
        }
    }

    if(trace(child, exit_status) != 0)
    {
        cleanup();
        db_close(1);
        restore_signals();
        return 1;
    }

    if(db_close(0) != 0)
    {
        /* LCOV_EXCL_START : Closing database shouldn't fail */
        restore_signals();
        return 1;
        /* LCOV_EXCL_STOP */
    }

    restore_signals();
    return 0;
}
