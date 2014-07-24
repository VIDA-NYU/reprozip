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


static void get_i386_reg(register_type *reg, uint64_t value)
{
    reg->i = (int32_t)value;
    reg->u = value;
    reg->p = (void*)value;
}

static void get_x86_64_reg(register_type *reg, uint64_t value)
{
    reg->i = (int64_t)value;
    reg->u = value;
    reg->p = (void*)value;
}


int trace_verbosity = 0;
#define verbosity trace_verbosity


struct Process **processes = NULL;
size_t processes_size;

struct Process *trace_find_process(pid_t tid)
{
    size_t i;
    for(i = 0; i < processes_size; ++i)
    {
        if(processes[i]->status != PROCESS_FREE && processes[i]->tid == tid)
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

    /* Count unknown processes */
    {
        size_t unknown = 0;
        for(i = 0; i < processes_size; ++i)
            if(processes[i]->status == PROCESS_UNKNOWN)
                ++unknown;
        {
            int many_unknown = unknown * 2 >= processes_size;
            if(many_unknown && verbosity >= 1)
                log_warn(0, "there are %u/%u UNKNOWN processes",
                         (unsigned int)unknown, (unsigned int)processes_size);
            else if(verbosity >= 2)
                log_info(0, "there are %u/%u UNKNOWN processes",
                         (unsigned int)unknown, (unsigned int)processes_size);
        }
    }

    /* Allocate more! */
    if(verbosity >= 3)
        log_info(0, "process table full (%d), reallocating",
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
            processes[i]->status = PROCESS_FREE;
        }
        return processes[prev_size];
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
        case PROCESS_FREE:
            break;
        case PROCESS_UNKNOWN:
            /* Exists but no corresponding syscall has returned yet */
            ++unknown;
        case PROCESS_ALLOCATED:
            /* Not yet attached but it will show up eventually */
        case PROCESS_ATTACHED:
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
            if(strncmp(pathname, binary, 4096) != 0
             && strncmp(previous_path, pathname, 4096) != 0)
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
            log_critical_(0, "waitpid failed: ");
            perror(NULL);
            return -1;
        }
        if(WIFEXITED(status))
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
                    return -1;
                free(process->wd);
                process->status = PROCESS_FREE;
            }
            trace_count_processes(&nprocs, &unknown);
            if(verbosity >= 2)
                log_info(tid, "process exited (%s %d), %d processes remain",
                         (exitcode & 0x0100)?"signal":"code", exitcode & 0xFF,
                         (unsigned int)nprocs);
            if(nprocs <= 0)
                break;
            if(unknown >= nprocs)
            {
                log_critical(0, "only UNKNOWN processes remaining (%d)",
                             (unsigned int)nprocs);
                return -1;
            }
            continue;
        }

        process = trace_find_process(tid);
        if(process == NULL)
        {
            if(verbosity >= 3)
                log_info(tid, "process appeared");
            process = trace_get_empty_process();
            process->status = PROCESS_UNKNOWN;
            process->tid = tid;
            process->in_syscall = 0;
            process->wd = NULL;
            trace_set_options(tid);
            /* Don't resume, it will be set to ATTACHED and resumed when fork()
             * returns */
            continue;
        }
        else if(process->status == PROCESS_ALLOCATED)
        {
            process->status = PROCESS_ATTACHED;

            if(verbosity >= 3)
                log_info(tid, "process attached");
            trace_set_options(tid);
            ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
            if(verbosity >= 2)
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
                ptrace(PTRACE_GETREGS, tid, NULL, &regs);
            }
#if defined(I386)
            if(!process->in_syscall || regs.orig_eax >= 0)
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
#elif defined(X86_64)
            /* On x86_64, process might be 32 or 64 bits */
            /* If len is known (not 0) and not that of x86_64 registers,
             * or if len is not known (0) and CS is 0x23 (not as reliable) */
            if( (len != 0 && len != sizeof(regs))
             || (len == 0 && regs.cs == 0x23) )
            {
                /* 32 bit mode */
                struct i386_regs *x86regs = (struct i386_regs*)&regs;
                if(!process->in_syscall || x86regs->orig_eax >= 0)
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
                if(!process->in_syscall || regs.orig_rax >= 0)
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
                return -1;
        }
        /* Handle signals */
        else if(WIFSTOPPED(status))
        {
            int signum = WSTOPSIG(status) & 0x7F;

            /* Synthetic signal for ptrace event: resume */
            if(signum == SIGTRAP && status & 0xFF0000)
                ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
            else if(signum == SIGTRAP)
            {
                /* Probably doesn't happen? Then, remove */
                log_warn(0,
                         "NOT delivering SIGTRAP to %d\n"
                         "    waitstatus=0x%X", tid, status);
                ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
            }
            /* Other signal, let the process handle it */
            else
            {
                siginfo_t si;
                if(verbosity >= 2)
                    log_info(tid, "caught signal %d", signum);
                if(ptrace(PTRACE_GETSIGINFO, tid, 0, (long)&si) >= 0)
                    ptrace(PTRACE_SYSCALL, tid, NULL, signum);
                else
                {
                    /* Not sure what this is for */
                    perror("    NOT delivering");
                    if(signum != SIGSTOP)
                        ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
                }
            }
        }
    }

    return 0;
}

static void cleanup(void)
{
    size_t i;
    {
        size_t nb = 0;
        for(i = 0; i < processes_size; ++i)
            if(processes[i]->status != PROCESS_FREE)
                ++nb;
        /* size_t size is implementation dependent; %u for size_t can trigger
         * a warning */
        log_info(0, "cleaning up, %u processes to kill...", (unsigned int)nb);
    }
    for(i = 0; i < processes_size; ++i)
    {
        if(processes[i]->status != PROCESS_FREE)
        {
            kill(processes[i]->tid, SIGKILL);
            free(processes[i]->wd);
        }
    }
}

static void sigint_handler(int signo)
{
    if(verbosity >= 1)
        log_info(0, "cleaning up on SIGINT");
    (void)signo;
    cleanup();
    exit(1);
}

static void trace_init(void)
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

    syscall_build_table();
}

int fork_and_trace(const char *binary, int argc, char **argv,
                   const char *database_path, int *exit_status)
{
    pid_t child;

    trace_init();

    child = fork();

    if(child != 0 && verbosity >= 2)
        log_info(0, "child created, pid=%d", child);

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
        log_critical_(0, "couldn't execute the target command (execvp "
                      "returned): ");
        perror(NULL);
        exit(1);
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
        /* We sent a SIGSTOP, but we resume on attach */
        process->tid = child;
        process->tgid = child;
        process->in_syscall = 0;
        process->wd = get_wd();

        if(verbosity >= 2)
            log_info(0, "process %d created by initial fork()", child);
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
