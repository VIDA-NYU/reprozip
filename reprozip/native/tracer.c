#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sched.h>
#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "database.h"
#include "ptrace_utils.h"
#include "utils.h"


#ifndef __X32_SYSCALL_BIT
#define __X32_SYSCALL_BIT 0x40000000
#endif

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif


int trace_verbosity = 0;
#define verbosity trace_verbosity


#define PROCESS_FREE        0   /* unallocated entry in table */
#define PROCESS_ALLOCATED   1   /* fork() done but not yet attached */
#define PROCESS_ATTACHED    2   /* running process */
#define PROCESS_UNKNOWN     3   /* attached but no corresponding fork() call
                                 * has finished yet */

struct Process {
    unsigned int identifier;
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

struct ExecveInfo {
    char *binary;
    char **argv;
    char **envp;
};

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
            if(verbosity >= 2 || (verbosity >= 1 && many_unknown) )
                fprintf(stderr, "%sthere are %u/%u UNKNOWN processes\n",
                        many_unknown?"Warning: ":"",
                        (unsigned int)unknown, (unsigned int)processes_size);
        }
    }

    /* Allocate more! */
    if(verbosity >= 3)
        fprintf(stderr, "Process table full (%d), reallocating\n",
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

#ifdef DEBUG_PROC_PARSER
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
#ifdef DEBUG_PROC_PARSER
                fprintf(stderr, "    adding to database\n");
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

char *trace_unhandled_syscall(int syscall, struct Process *process)
{
    const char *name = NULL;
    int type = 0;
    switch(syscall)
    {
    /* Path as first argument */
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
    case SYS_mq_open:
        name = "mq_open";
        break;
    case SYS_mq_unlink:
        name = "mq_unlink";
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
    case SYS_faccessat:
        name = "faccessat"; type = 2;
        break;
    case SYS_readlinkat:
        name = "readlinkat"; type = 2;
        break;
#ifdef SYS_fstatat
    case SYS_fstatat:
#endif
#ifdef SYS_fstatat64
    case SYS_fstatat64:
#endif
#ifdef SYS_newfstatat
    case SYS_newfstatat:
#endif
        name = "fstatat"; type = 2;
        break;

    /* Others */
    case SYS_ptrace:
        name = "ptrace"; type = 2;
        break;
#ifdef SYS_name_to_handle_at
    case SYS_name_to_handle_at:
        name = "name_to_handle_at"; type = 2;
        break;
#endif
    }

    if(name == NULL)
        return NULL;
    else if(type == 0)
    {
        char *pathname = tracee_strdup(process->tid,
                                       (void*)process->params[0]);
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

static void print_sockaddr(FILE *stream, void *address, socklen_t addrlen)
{
    const short family = ((struct sockaddr*)address)->sa_family;
    if(family == AF_INET && addrlen >= sizeof(struct sockaddr_in))
    {
        struct sockaddr_in *address_ = address;
        fprintf(stream, "%s:%d",
                inet_ntoa(address_->sin_addr),
                ntohs(address_->sin_port));
    }
    else if(family == AF_INET6
          && addrlen >= sizeof(struct sockaddr_in6))
    {
        struct sockaddr_in6 *address_ = address;
        char buf[50];
        inet_ntop(AF_INET6, &address_->sin6_addr, buf, sizeof(buf));
        fprintf(stream, "[%s]:%d", buf, ntohs(address_->sin6_port));
    }
    else
        fprintf(stream, "<unknown destination, sa_family=%d>", family);
}

int trace_handle_syscall(struct Process *process)
{
    pid_t tid = process->tid;
    const int syscall = process->current_syscall;

    /* ********************
     * open(), creat(), access()
     */
    if(process->in_syscall && (syscall == SYS_open || syscall == SYS_creat
        || syscall == SYS_access) )
    {
        unsigned int mode;
        char *pathname = tracee_strdup(tid, (void*)process->params[0]);
        if(pathname[0] != '/')
        {
            char *oldpath = pathname;
            pathname = abspath(process->wd, oldpath);
            free(oldpath);
        }

        if(syscall == SYS_access)
            mode = FILE_STAT;
        else if(syscall == SYS_creat)
            mode = flags2mode(process->params[1] |
                              O_CREAT | O_WRONLY | O_TRUNC);
        else /* syscall == SYS_open */
            mode = flags2mode(process->params[1]);

        if(verbosity >= 3)
        {
            /* Converts mode to string s_mode */
            char mode_buf[42] = "";
            const char *s_mode;
            if(mode & FILE_READ)
                strcat(mode_buf, "|FILE_READ");
            if(mode & FILE_WRITE)
                strcat(mode_buf, "|FILE_WRITE");
            if(mode & FILE_WDIR)
                strcat(mode_buf, "|FILE_WDIR");
            if(mode & FILE_STAT)
                strcat(mode_buf, "|FILE_STAT");
            s_mode = mode_buf[0]?mode_buf + 1:"0";

            if(syscall == SYS_open)
                fprintf(stderr, "open(\"%s\", mode=%s) = %d (%s)\n",
                        pathname,
                        s_mode,
                        (int)process->retvalue,
                        (process->retvalue >= 0)?"success":"failure");
            else /* SYS_creat or SYS_access */
                fprintf(stderr, "%s(\"%s\") (mode=%s) = %d (%s)\n",
                        (syscall == SYS_open)?"open":
                            (syscall == SYS_creat)?"creat":"access",
                        pathname,
                        s_mode,
                        (int)process->retvalue,
                        (process->retvalue >= 0)?"success":"failure");
        }

        if(process->retvalue >= 0)
        {
            if(db_add_file_open(process->identifier,
                                pathname,
                                mode,
                                path_is_dir(pathname)) != 0)
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
        char *pathname = tracee_strdup(tid, (void*)process->params[0]);
        if(pathname[0] != '/')
        {
            char *oldpath = pathname;
            pathname = abspath(process->wd, oldpath);
            free(oldpath);
        }
        if(verbosity >= 3)
        {
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
        }
        if(process->retvalue >= 0)
        {
            if(db_add_file_open(process->identifier,
                                pathname,
                                FILE_STAT,
                                path_is_dir(pathname)) != 0)
                return -1;
        }
        free(pathname);
    }
    /* ********************
     * readlink()
     */
    else if(process->in_syscall && syscall == SYS_readlink)
    {
        char *pathname = tracee_strdup(tid, (void*)process->params[0]);
        if(pathname[0] != '/')
        {
            char *oldpath = pathname;
            pathname = abspath(process->wd, oldpath);
            free(oldpath);
        }
        if(verbosity >= 3)
        {
            fprintf(stderr, "readlink(\"%s\") = %d (%s)\n",
                    pathname,
                    (int)process->retvalue,
                    (process->retvalue >= 0)?"success":"failure");
        }
        if(process->retvalue >= 0)
        {
            if(db_add_file_open(process->identifier,
                                pathname,
                                FILE_STAT,
                                0) != 0)
                return -1;
        }
        free(pathname);
    }
    /* ********************
     * mkdir()
     */
    else if(process->in_syscall && syscall == SYS_mkdir)
    {
        char *pathname = tracee_strdup(tid, (void*)process->params[0]);
        if(pathname[0] != '/')
        {
            char *oldpath = pathname;
            pathname = abspath(process->wd, oldpath);
            free(oldpath);
        }
        if(verbosity >= 3)
        {
            fprintf(stderr, "mkdir(\"%s\") = %d (%s)\n", pathname,
                    (int)process->retvalue,
                    (process->retvalue >= 0)?"success":"failure");
        }
        if(process->retvalue >= 0)
        {
            if(db_add_file_open(process->identifier,
                                pathname,
                                FILE_WRITE,
                                1) != 0)
                return -1;
        }
    }
    /* ********************
     * symlink()
     */
    else if(process->in_syscall && syscall == SYS_symlink)
    {
        char *pathname = tracee_strdup(tid, (void*)process->params[1]);
        if(pathname[0] != '/')
        {
            char *oldpath = pathname;
            pathname = abspath(process->wd, oldpath);
            free(oldpath);
        }
        if(verbosity >= 3)
        {
            fprintf(stderr, "symlink(\"%s\") = %d (%s)\n", pathname,
                    (int)process->retvalue,
                    (process->retvalue >= 0)?"success":"failure");
        }
        if(process->retvalue >= 0)
        {
            if(db_add_file_open(process->identifier,
                                pathname,
                                FILE_WRITE,
                                1) != 0)
                return -1;
        }
    }
    /* ********************
     * chdir()
     */
    else if(process->in_syscall && syscall == SYS_chdir)
    {
        char *pathname = tracee_strdup(tid, (void*)process->params[0]);
        if(pathname[0] != '/')
        {
            char *oldpath = pathname;
            pathname = abspath(process->wd, oldpath);
            free(oldpath);
        }
        if(verbosity >= 3)
        {
            fprintf(stderr, "chdir(\"%s\") = %d (%s)\n", pathname,
                    (int)process->retvalue,
                    (process->retvalue >= 0)?"success":"failure");
        }
        if(process->retvalue >= 0)
        {
            free(process->wd);
            process->wd = pathname;
            if(db_add_file_open(process->identifier,
                                pathname,
                                FILE_WDIR,
                                1) != 0)
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
        execi->binary = tracee_strdup(tid, (void*)process->params[0]);
        if(execi->binary[0] != '/')
        {
            char *oldbin = execi->binary;
            execi->binary = abspath(process->wd, oldbin);
            free(oldbin);
        }
        execi->argv = tracee_strarraydup(tid, (void*)process->params[1]);
        execi->envp = tracee_strarraydup(tid, (void*)process->params[2]);
        if(verbosity >= 3)
        {
            fprintf(stderr, "execve called by %d:\n  binary=%s\n  argv:\n",
                    tid, execi->binary);
            {
                /* Note: this conversion is correct and shouldn't need a
                 * cast */
                const char *const *v = (const char* const*)execi->argv;
                while(*v)
                {
                    fprintf(stderr, "    %s\n", *v);
                    ++v;
                }
            }
            {
                size_t nb = 0;
                while(execi->envp[nb] != NULL)
                    ++nb;
                fprintf(stderr, "  envp: (%u entries)\n", (unsigned int)nb);
            }
        }
        process->syscall_info = execi;
    }
    else if(process->in_syscall && syscall == SYS_execve)
    {
        struct ExecveInfo *execi = process->syscall_info;
        if(process->retvalue >= 0)
        {
            /* Note: execi->argv needs a cast to suppress a bogus warning
             * While conversion from char** to const char** is invalid,
             * conversion from char** to const char*const* is, in fact, safe.
             * G++ accepts it, GCC issues a warning. */
            if(db_add_exec(process->identifier, execi->binary,
                           (const char *const*)execi->argv,
                           (const char *const*)execi->envp,
                           process->wd) != 0)
                return -1;
            if(verbosity >= 2)
                fprintf(stderr, "Proc %d successfully exec'd %s\n",
                        process->tid, execi->binary);
            /* Process will get SIGTRAP with PTRACE_EVENT_EXEC */
            if(trace_add_files_from_proc(process->identifier, process->tid,
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
#ifndef CLONE_THREAD
#define CLONE_THREAD 0x00010000
#endif
        if(process->retvalue > 0)
        {
            int is_thread = 0;
            pid_t new_tid = process->retvalue;
            struct Process *new_process;
            if(syscall == SYS_clone)
                is_thread = ((unsigned int)process->params[0]) & CLONE_THREAD;
            if(verbosity >= 2)
                fprintf(stderr,
                        "Process %d created by %d via %s\n"
                        "    (thread: %s) (working directory: %s)\n",
                        new_tid, process->tid,
                        (syscall == SYS_fork)?"fork()":
                        (syscall == SYS_vfork)?"vfork()":
                        "clone()",
                        is_thread?"yes":"no",
                        process->wd);

            /* At this point, the process might have been seen by waitpid in
             * trace() or not. */
            new_process = trace_find_process(new_tid);
            if(new_process != NULL)
            {
                /* Process has been seen before and options were set */
                if(new_process->status != PROCESS_UNKNOWN)
                {
                    fprintf(stderr, "Critical: just created process that is "
                            "already running (status=%d)\n",
                            new_process->status);
                    return -1;
                }
                new_process->status = PROCESS_ATTACHED;
                ptrace(PTRACE_SYSCALL, new_process->tid, NULL, NULL);
                if(verbosity >= 2)
                {
                    unsigned int nproc, unknown;
                    trace_count_processes(&nproc, &unknown);
                    fprintf(stderr, "%d processes (inc. %d unattached)\n",
                            nproc, unknown);
                }
            }
            else
            {
                /* Process hasn't been seen before (syscall returned first) */
                new_process = trace_get_empty_process();
                new_process->status = PROCESS_ALLOCATED;
                /* New process gets a SIGSTOP, but we resume on attach */
                new_process->tid = new_tid;
                new_process->in_syscall = 0;
            }
            if(is_thread)
                new_process->tgid = process->tgid;
            else
                new_process->tgid = new_process->tid;
            new_process->wd = strdup(process->wd);

            /* Parent will also get a SIGTRAP with PTRACE_EVENT_FORK */

            if(db_add_process(&new_process->identifier,
                              process->identifier,
                              process->wd) != 0)
                return -1;
        }
    }
    /* ********************
     * Network connections
     */
    else if(verbosity >= 1 && process->in_syscall && process->retvalue >= 0
          && (0
#ifdef SYS_socketcall
            || (syscall == SYS_socketcall && process->params[0] == SYS_ACCEPT)
#endif
#ifdef SYS_accept
            || syscall == SYS_accept
#endif
#ifdef SYS_accept4
            || syscall == SYS_accept4
#endif
              ) )
    {
        socklen_t addrlen;
        register_type arg1;
        register_type arg2;
#ifdef SYS_socketcall
        if(syscall == SYS_socketcall)
        {
            arg1 = process->params[2];
            arg2 = process->params[3];
        }
        else
#endif
        {
            arg1 = process->params[1];
            arg2 = process->params[2];
        }
        tracee_read(tid, (void*)&addrlen, (void*)arg2, sizeof(addrlen));
        if(addrlen >= sizeof(short))
        {
            void *address = malloc(addrlen);
            tracee_read(tid, address, (void*)arg1, addrlen);
            fprintf(stderr, "Warning: process accepted a connection from ");
            print_sockaddr(stderr, address, addrlen);
            fprintf(stderr, "\n");
            free(address);
        }
    }
    else if(verbosity >= 1 && process->in_syscall && process->retvalue >= 0
          && (0
#ifdef SYS_socketcall
            || (syscall == SYS_socketcall && process->params[0] == SYS_CONNECT)
#endif
#ifdef SYS_connect
            || syscall == SYS_connect
#endif
              ) )
    {
        socklen_t addrlen;
        register_type arg1;
#ifdef SYS_socketcall
        if(syscall == SYS_socketcall)
        {
             arg1 = process->params[2];
             addrlen = process->params[3];
        }
        else
#endif
        {
             arg1 = process->params[1];
             addrlen = process->params[2];
        }
        if(addrlen >= sizeof(short))
        {
            void *address = malloc(addrlen);
            tracee_read(tid, address, (void*)arg1, addrlen);
            fprintf(stderr, "Warning: process connected to ");
            print_sockaddr(stderr, address, addrlen);
            fprintf(stderr, "\n");
            free(address);
        }
    }
    /* ********************
     * Other syscalls that might be of interest but that we don't handle yet
     */
    else if(verbosity >= 1 && process->in_syscall && process->retvalue >= 0)
    {
        char *desc = trace_unhandled_syscall(syscall, process);
        if(desc != NULL)
        {
            fprintf(stderr,
                    "WARNING: process %d used unhandled system call %s\n",
                    process->tid, desc);
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
    ptrace(PTRACE_SYSCALL, tid, NULL, NULL);

    return 0;
}

void trace_set_options(pid_t tid)
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

int trace(pid_t first_proc, int *first_exit_code)
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
            perror("waitpid failed");
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
                fprintf(stderr,
                        "Process %d exited (%s %d), %d processes remain\n",
                        tid,
                        (exitcode & 0x0100)?"signal":"code", exitcode & 0xFF,
                        (unsigned int)nprocs);
            if(nprocs <= 0)
                break;
            if(unknown >= nprocs)
            {
                fprintf(stderr, "Critical: only UNKNOWN processes remaining "
                        "(%d)\n", (unsigned int)nprocs);
                return -1;
            }
            continue;
        }

        process = trace_find_process(tid);
        if(process == NULL)
        {
            if(verbosity >= 3)
                fprintf(stderr, "Process %d appeared\n", tid);
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
                fprintf(stderr, "Process %d attached\n", tid);
            trace_set_options(tid);
            ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
            if(verbosity >= 2)
            {
                unsigned int nproc, unknown;
                trace_count_processes(&nproc, &unknown);
                fprintf(stderr, "%d processes (inc. %d unattached)\n",
                        nproc, unknown);
            }
            continue;
        }

        if(WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
        {
            struct user_regs_struct regs;
            size_t len = 0;
            /* Try to use GETREGSET first, since iov_len allows us to know if
             * 32bit or 64bit mode was used */
#ifdef PTRACE_GETREGSET
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
            /* TODO : handle i386 compat and x32 (currently just warns) */
            /* If len is known (not 0) and not that of x86_64 registers,
             * or if len is not known (0) and CS is 0x23 (not as reliable) */
            if( (len != 0 && len != sizeof(regs))
             || (len == 0 && regs.cs == 0x23))
            {
                if(verbosity >= 1)
                    fprintf(stderr, "Warning: process %d made a syscall in "
                            "i386 compat mode\n", tid);
            }
            else
            {
                process->current_syscall = regs.orig_rax;
                if(process->in_syscall)
                    process->retvalue = regs.rax;
                else
                {
                    if(process->current_syscall & __X32_SYSCALL_BIT)
                    {
                        if(verbosity >= 1)
                            fprintf(stderr, "Warning: process %d made an x32 "
                                    "syscall\n", tid);
                    }
                    process->params[0] = regs.rdi;
                    process->params[1] = regs.rsi;
                    process->params[2] = regs.rdx;
                    process->params[3] = regs.r10;
                    process->params[4] = regs.r8;
                    process->params[5] = regs.r9;
                }
            }
#endif
            if(trace_handle_syscall(process) != 0)
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
                fprintf(stderr, "NOT delivering SIGTRAP to %d\n",
                        tid);
                fprintf(stderr, "    waitstatus=0x%X\n", status);
                ptrace(PTRACE_SYSCALL, tid, NULL, NULL);
            }
            /* Other signal, let the process handle it */
            else
            {
                siginfo_t si;
                if(verbosity >= 2)
                    fprintf(stderr, "Process %d caught signal %d\n",
                            tid, signum);
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

void cleanup(void)
{
    size_t i;
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
    for(i = 0; i < processes_size; ++i)
    {
        if(processes[i]->status != PROCESS_FREE)
        {
            kill(processes[i]->tid, SIGKILL);
            free(processes[i]->wd);
        }
    }
}

void sigint_handler(int signo)
{
    if(verbosity >= 1)
        fprintf(stderr, "Cleaning up on SIGINT\n");
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

    if(child != 0 && verbosity >= 2)
        fprintf(stderr, "Child created, pid=%d\n", child);

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
            fprintf(stderr, "Process %d created by initial fork()\n", child);
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
