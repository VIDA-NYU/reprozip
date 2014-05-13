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

char *tracee_strdup(pid_t pid, size_t ptr)
{
    size_t length = tracee_strlen(pid, ptr);
    char *str = malloc(length + 1);
    tracee_read(pid, str, ptr, length);
    str[length] = '\0';
    return str;
}

char **tracee_strarraydup(pid_t pid, size_t ptr)
{
    char **array;
    /* Reads number of pointers in pointer array */
    size_t nb_args = 0;
    const char *const *const argv = (void*)ptr;
    {
        const char *const *a = argv;
        /* xargv = *a */
        const char *xargv = (void*)ptrace(PTRACE_PEEKDATA, pid, a, NULL);
        while(xargv != NULL)
        {
            ++nb_args;
            ++a;
            xargv = (void*)ptrace(PTRACE_PEEKDATA, pid, a, NULL);
        }
    }
    /* Allocs pointer array */
    array = malloc((nb_args + 1) * sizeof(char*));
    /* Dups array elements */
    {
        size_t i = 0;
        /* xargv = argv[0] */
        const char *xargv = (void*)ptrace(PTRACE_PEEKDATA, pid, argv, NULL);
        while(xargv != NULL)
        {
            array[i] = tracee_strdup(pid, (size_t)xargv);
            ++i;
            /* xargv = argv[i] */
            xargv = (void*)ptrace(PTRACE_PEEKDATA, pid, argv + i, NULL);
        }
        array[i] = NULL;
    }
    return array;
}


/* *************************************
 * Tracer
 */

#define PROCESS_FREE        0
#define PROCESS_ALLOCATED   1
#define PROCESS_ATTACHED    2

struct Process {
    unsigned int identifier;
    pid_t pid;
    int status;
    int in_syscall;
    int current_syscall;
    size_t retvalue;
    size_t params[6];
    void *syscall_info;
};

struct ExecveInfo {
    char *binary;
    char **argv;
};

struct Process **processes;
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
            processes[i]->current_syscall = -1;
            processes[i]->syscall_info = NULL;
        }
        return ret;
    }
}

static unsigned int flags2mode(int flags)
{
    unsigned int mode = 0;
    if(!O_RDONLY)
    {
        if(flags & O_WRONLY)
            mode |= FILE_WRITE;
        else if(flags & O_RDWR)
            mode |= FILE_READ | FILE_WRITE;
        else
            mode |= FILE_READ;
    }
    else if(!O_WRONLY)
    {
        if(flags & O_RDONLY)
            mode |= FILE_READ;
        else if(flags & O_RDWR)
            mode |= FILE_READ | FILE_WRITE;
        else
            mode |= FILE_WRITE;
    }
    else
    {
        if( (flags & (O_RDONLY | O_WRONLY)) == (O_RDONLY | O_WRONLY) )
            fprintf(stderr, "Error: encountered bogus open() flags "
                    "O_RDONLY|O_WRONLY\n");
            /* Carry on anyway */
        if(flags & O_RDONLY)
            mode |= FILE_READ;
        if(flags & O_WRONLY)
            mode |= FILE_WRITE;
        if(flags & O_RDWR)
            mode |= FILE_READ | FILE_WRITE;
    }
    return mode;
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
    if(process->in_syscall && syscall == SYS_open)
    {
        /* FIXME : this cast doesn't look too safe */
        int ret = process->retvalue;
        unsigned int mode;
        char *pathname = tracee_strdup(pid, process->params[0]);
#ifdef DEBUG
        fprintf(stderr, "open(\"%s\") = %d (%s)\n", pathname, ret,
                (ret >= 0)?"success":"failure");
#endif
        if(ret >= 0)
        {
            mode = flags2mode((int)process->params[1]);
            if(db_add_file_open(process->identifier,
                                pathname,
                                mode) != 0)
                return -1;
        }
        free(pathname);
    }
    else if(!process->in_syscall && syscall == SYS_execve)
    {
        /* int execve(const char *filename,
         *            char *const argv[],
         *            char *const envp[]); */
        struct ExecveInfo *execi = malloc(sizeof(struct ExecveInfo));
#ifdef DEBUG
        fprintf(stderr, "Entering execve, getting arguments...\n");
#endif
        execi->binary = tracee_strdup(pid, process->params[0]);
        execi->argv = tracee_strarraydup(pid, process->params[1]);
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
#endif
        /* TODO : record envp? */
        process->syscall_info = execi;
    }
    else if(process->in_syscall && syscall == SYS_execve)
    {
        /* FIXME : this cast doesn't look too safe */
        int ret = process->retvalue;
        struct ExecveInfo *execi = process->syscall_info;
        if(ret >= 0)
        {
            /* Note: exec->argv needs cast to suppress a bogus GCC warning
             * While conversion from char** to const char** is invalid,
             * conversion from char** to const char*const* is, in fact, safe.
             * G++ accepts it, GCC issues a warning */
            if(db_add_exec(process->identifier, execi->binary,
                           (const char *const*)execi->argv) != 0)
                return -1;
        }
        {
            char **ptr = execi->argv;
            while(*ptr)
            {
                free(*ptr);
                ++ptr;
            }
            free(execi->argv);
            free(execi->binary);
            free(execi);
        }
    }
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
            if(db_add_process(&new_process->identifier,
                              process->identifier) != 0)
                return -1;
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

int trace(void)
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
            fprintf(stderr, "Warning: found unexpected process %d\n", pid);
            process = trace_get_empty_process();
            process->status = PROCESS_ALLOCATED;
            process->pid = pid;
            process->in_syscall = 0;
            if(db_add_first_process(&process->identifier) != 0)
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
            kill(processes[i]->pid, SIGKILL);
    }
}

void sigint_handler(int signo)
{
    cleanup();
    exit(1);
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
        processes[i]->current_syscall = -1;
        processes[i]->syscall_info = NULL;
    }

    signal(SIGINT, sigint_handler);
}


/* *************************************
 * Entry point
 */

int fork_and_trace(const char *binary, int argc, char **argv,
                   const char *database_path)
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

        fprintf(stderr, "Process %d created by initial fork()\n", child);
        if(db_add_first_process(&process->identifier) != 0)
        {
            cleanup();
            return 1;
        }
    }

    if(trace() != 0)
    {
        cleanup();
        db_close();
        return 1;
    }

    if(db_close() != 0)
        return 1;

    return 0;
}
