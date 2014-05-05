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


/* *************************************
 * Tracee-manipulating functions
 */

size_t tracee_strlen(pid_t pid, size_t ptr)
{
    size_t j = ptr % WORD_SIZE;
    size_t i = ptr - j;
    size_t size = 0;
    int done = 0;
    for(; !done; i += WORD_SIZE)
    {
        unsigned int data = ptrace(PTRACE_PEEKDATA, pid, i, NULL);
        for(; !done && j < WORD_SIZE; ++j)
        {
            unsigned char byte = data >> (8 * j);
            if(byte == 0)
                done = 1;
            else
                ++size;
        }
        j = 0;
    }
    return size;
}

void tracee_read(pid_t pid, char *dst, size_t ptr, size_t size)
{
    size_t j = ptr % WORD_SIZE;
    size_t i = ptr - j;
    size_t end = ptr + size;
    for(; i < end; i += WORD_SIZE)
    {
        unsigned int data = ptrace(PTRACE_PEEKDATA, pid, i, NULL);
        for(; j < WORD_SIZE && i + j < end; ++j)
            *dst++ = data >> (8 * j);
        j = 0;
    }
}


/* *************************************
 * Tracer
 */

#define PROCESS_FREE        0
#define PROCESS_ALLOCATED   1
#define PROCESS_ATTACHED    2

struct Syscall {
    int n;
    char *path;
    int mode;
};

struct Process {
    unsigned int identifier;
    pid_t pid;
    int status;
    int in_syscall;
    struct Syscall current_syscall;
};

struct Process **processes;
size_t processes_size;
unsigned int next_identifier = 0;

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

struct Process *trace_get_empty_process()
{
    size_t i;
    for(i = 0; i < processes_size; ++i)
    {
        if(processes[i]->status == PROCESS_FREE)
            return processes[i];
    }

    /* Allocate more! */
    {
        struct Process *pool, *ret;
        processes_size *= 2;
        pool = malloc((processes_size - i) * sizeof(*pool));
        processes = realloc(processes, processes_size);
        ret = processes[i];
        for(; i < processes_size; ++i)
        {
            processes[i] = pool++;
            processes[i]->status = PROCESS_FREE;
            processes[i]->in_syscall = 0;
            processes[i]->current_syscall.n = -1;
        }
        return ret;
    }
}

void trace_handle_syscall(struct Process *process, int syscall, size_t *params)
{
    pid_t pid = process->pid;
#ifdef DEBUG
    fprintf(stderr, "syscall=%u, in_syscall=%u\n", syscall, process->in_syscall);
#endif
    if(!process->in_syscall
     && (syscall == SYS_open || syscall == SYS_execve) )
    {
        size_t pathname_addr = params[0];
        int flags = (int)params[1];
        size_t pathname_size = tracee_strlen(pid, pathname_addr);
        char *pathname = malloc(pathname_size + 1);
        tracee_read(pid, pathname, pathname_addr, pathname_size);
        pathname[pathname_size] = '\0';
        process->current_syscall.n = syscall;
        process->current_syscall.path = pathname;
        if(syscall == SYS_execve)
           process->current_syscall.mode = FILE_EXEC;
        else
        {
            unsigned int mode = 0;
            if( (flags & (O_RDONLY | O_WRONLY)) == (O_RDONLY | O_WRONLY) )
                fprintf(stderr, "Error: process %d used open() flags "
                        "O_RDONLY|O_WRONLY\n", process->pid);
                /* Carry on anyway */
            if(flags & O_RDONLY)
                mode |= FILE_READ;
            if(flags & O_WRONLY)
                mode |= FILE_WRITE;
            if(flags & O_RDWR)
                mode |= FILE_READ | FILE_WRITE;
            if(mode == 0)
                fprintf(stderr, "mode=0! flags=%d\n", flags);
            process->current_syscall.mode = mode;
        }
    }
    else if(process->in_syscall
          && (syscall == SYS_open || syscall == SYS_execve) )
    {
        int ret = params[0];
        if(ret >= 0)
            db_add_file_open(process->identifier,
                             process->current_syscall.path,
                             process->current_syscall.mode);
        free(process->current_syscall.path);
        process->current_syscall.n = -1;
    }

    /* Run to next syscall */
    process->in_syscall = 1 - process->in_syscall;
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
}

void trace()
{
    int nprocs = 0;
    for(;;)
    {
        int status;
        pid_t pid;
        struct Process *process;

        /* Wait for a process */
        pid = waitpid(-1, &status, 0);
#ifdef DEBUG
        fprintf(stderr, "\npid=%d, status=%u\n", pid, status);
#endif
        if(WIFEXITED(status))
        {
            fprintf(stderr, "process %d exited, %d processes remain\n",
                    pid, nprocs-1);
            process = trace_find_process(pid);
            if(process != NULL)
                process->status = PROCESS_FREE;
            --nprocs;
            if(nprocs <= 0)
                break;
            continue;
        }

        process = trace_find_process(pid);
        if(process == NULL)
        {
#ifdef DEBUG
            fprintf(stderr, "Allocating Process for %d\n", pid);
#endif
            process = trace_get_empty_process();
            process->identifier = next_identifier++;
            process->status = PROCESS_ATTACHED;
            process->pid = pid;

            fprintf(stderr, "Process %d attached\n", pid);
            db_add_first_process(process->identifier, "unknown", 0, NULL);
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
        else
            fprintf(stderr, "Process %d is known (process=%p)\n", pid, process);
#endif

#ifdef DEBUG
        if(WIFSTOPPED(status))
        {
            if(WSTOPSIG(status) & 0x80)
                fprintf(stderr, "Process %d stopped because of syscall "
                        "tracing\n", pid);
            else
                fprintf(stderr, "Process %d stopped elsewhere (WSTOPSIG=%u)\n",
                        pid, WSTOPSIG(status));
        }
        else
            fprintf(stderr, "Process %d is NOT stopped\n", pid);
#endif

        if(WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
        {
            int syscall;
            size_t params[6];
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
#if defined(I386)
            syscall = regs.orig_eax;
            params[0] = regs.ebx;
            params[1] = regs.ecx;
            params[2] = regs.edx;
            params[3] = regs.esi;
            params[4] = regs.edi;
            params[5] = regs.ebp;
#elif defined(X86_64)
            syscall = regs.orig_rax;
            params[0] = regs.rdi;
            params[1] = regs.rsi;
            params[2] = regs.rdx;
            params[3] = regs.r10;
            params[4] = regs.r8;
            params[5] = regs.r9;
#endif
            trace_handle_syscall(process, syscall, params);
        }
        /* Continue on SIGTRAP */
        else if(WIFSTOPPED(status))
        {
#ifdef DEBUG
            fprintf(stderr, "Resuming on signal\n");
#endif
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        }
    }
}

void trace_init(void)
{
    size_t i;
    struct Process *pool;
    signal(SIGCHLD, SIG_DFL);
    processes_size = 16;
    processes = malloc(processes_size * sizeof(*processes));
    pool = malloc(processes_size * sizeof(*pool));
    for(i = 0; i < processes_size; ++i)
    {
        processes[i] = pool++;
        processes[i]->status = PROCESS_FREE;
        processes[i]->in_syscall = 0;
        processes[i]->current_syscall.n = -1;
    }
}


/* *************************************
 * Entry point
 */

int main(int argc, char **argv)
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
        char **args = malloc(argc * sizeof(char*));
        memcpy(args, argv + 1, (argc - 1) * sizeof(char*));
        args[argc - 1] = NULL;
        /* Trace this process */
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        /* Stop this once so tracer can set options */
        kill(getpid(), SIGSTOP);
        /* Execute the target */
        execvp(args[0], args);
        perror("Couldn't execute the target command (execvp returned)");
        return 1;
    }

#ifdef DEBUG
    fprintf(stderr, "Debug mode, using database on disk\n");
    unlink("./database.sqlite3");
    if(db_init("./database.sqlite3") != 0)
#else
    if(db_init("") != 0)
#endif
    {
        kill(child, SIGKILL);
        return 1;
    }

    trace();

    return db_close();
}
