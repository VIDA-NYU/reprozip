#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define WORD_SIZE sizeof(int)

#if !defined(X86) && !defined(X86_64)
#   if defined(__x86_64__) || defined(__x86_64)
#       define X86_64
#   elif defined(__i386__) || defined(__i386) || defined(_M_I86) || defined(_M_IX86)
#       define I386
#   else
#       error Unrecognized architecture!
#   endif
#endif


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

struct Process {
    pid_t pid;
    int attached;
};

struct Process processes[16];

struct Process *trace_find_process(pid_t pid)
{
    size_t i;
    for(i = 0; i < 16; ++i)
    {
        if(processes[i].attached && processes[i].pid == pid)
            return &processes[i];
    }
    return NULL;
}

struct Process *trace_get_empty_process()
{
    size_t i;
    for(i = 0; i < 16; ++i)
    {
        if(!processes[i].attached)
            return &processes[i];
    }
    return NULL;
}

void trace(pid_t pid)
{
    int status;

    /* Check process status */
    waitpid(pid, &status, 0);
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

    for(;;)
    {
        /* Run to next syscall */
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

        /* Check process status */
        waitpid(pid, &status, 0);
        if(WIFEXITED(status))
            break;

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
            if(syscall == SYS_open)
            {
                size_t pathname_addr = params[0];
                size_t pathname_size = tracee_strlen(pid, pathname_addr);
                char *pathname = malloc(pathname_size + 1);
                tracee_read(pid, pathname, pathname_addr, pathname_size);
                printf("open(%s)\n", pathname);
                free(pathname);
            }
        }
    }
}

void trace_init(void)
{
    size_t i;
    signal(SIGCHLD, SIG_DFL);
    for(i = 0; i < 16; ++i)
        processes[i].attached = 0;
}


/* *************************************
 * Entry point
 */

int main(int argc, char **argv)
{
    pid_t child;

    trace_init();

    child = fork();

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
    }

    trace(child);

    return 0;
}
