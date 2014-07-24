#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sched.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "database.h"
#include "log.h"
#include "ptrace_utils.h"
#include "syscalls.h"
#include "tracer.h"
#include "utils.h"


#ifndef __X32_SYSCALL_BIT
#define __X32_SYSCALL_BIT 0x40000000
#endif


#define verbosity trace_verbosity

struct ExecveInfo {
    char *binary;
    char **argv;
    char **envp;
};


static char *syscall_unhandled(int syscall, struct Process *process)
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
                                       process->params[0].p);
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

int syscall_handle(struct Process *process)
{
    pid_t tid = process->tid;
    const int syscall = process->current_syscall;
    if(verbosity >= 4)
    {
#ifdef I386
        fprintf(stderr, "syscall %d (I386)\n", syscall);
#else
        if(process->mode == MODE_I386)
            fprintf(stderr, "syscall %d (i386)\n", syscall);
        else
            fprintf(stderr, "syscall %d (%s)\n", syscall,
                    (process->current_syscall & __X32_SYSCALL_BIT)?
                        "x32":
                        "x64");
#endif
    }

    /* ********************
     * open(), creat(), access()
     */
    if(process->in_syscall && (syscall == SYS_open || syscall == SYS_creat
        || syscall == SYS_access) )
    {
        unsigned int mode;
        char *pathname = tracee_strdup(tid, process->params[0].p);
        if(pathname[0] != '/')
        {
            char *oldpath = pathname;
            pathname = abspath(process->wd, oldpath);
            free(oldpath);
        }

        if(syscall == SYS_access)
            mode = FILE_STAT;
        else if(syscall == SYS_creat)
            mode = flags2mode(process->params[1].u |
                              O_CREAT | O_WRONLY | O_TRUNC);
        else /* syscall == SYS_open */
            mode = flags2mode(process->params[1].u);

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
                log_info("open(\"%s\", mode=%s) = %d (%s)",
                         pathname,
                         s_mode,
                         (int)process->retvalue.i,
                         (process->retvalue.i >= 0)?"success":"failure");
            else /* SYS_creat or SYS_access */
                log_info("%s(\"%s\") (mode=%s) = %d (%s)",
                         (syscall == SYS_open)?"open":
                             (syscall == SYS_creat)?"creat":"access",
                         pathname,
                         s_mode,
                         (int)process->retvalue.i,
                         (process->retvalue.i >= 0)?"success":"failure");
        }

        if(process->retvalue.i >= 0)
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
        char *pathname = tracee_strdup(tid, process->params[0].p);
        if(pathname[0] != '/')
        {
            char *oldpath = pathname;
            pathname = abspath(process->wd, oldpath);
            free(oldpath);
        }
        if(verbosity >= 3)
        {
            log_info("%s(\"%s\") = %d (%s)",
                     (syscall == SYS_stat
#ifdef SYS_stat64
                    || syscall == SYS_stat64
#endif
#ifdef SYS_oldstat
                    || syscall == SYS_oldstat
#endif
                      )?"stat":"lstat",
                     pathname,
                     (int)process->retvalue.i,
                     (process->retvalue.i >= 0)?"success":"failure");
        }
        if(process->retvalue.i >= 0)
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
        char *pathname = tracee_strdup(tid, process->params[0].p);
        if(pathname[0] != '/')
        {
            char *oldpath = pathname;
            pathname = abspath(process->wd, oldpath);
            free(oldpath);
        }
        if(verbosity >= 3)
        {
            log_info("readlink(\"%s\") = %d (%s)",
                     pathname,
                     (int)process->retvalue.i,
                     (process->retvalue.i >= 0)?"success":"failure");
        }
        if(process->retvalue.i >= 0)
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
        char *pathname = tracee_strdup(tid, process->params[0].p);
        if(pathname[0] != '/')
        {
            char *oldpath = pathname;
            pathname = abspath(process->wd, oldpath);
            free(oldpath);
        }
        if(verbosity >= 3)
        {
            log_info("mkdir(\"%s\") = %d (%s)", pathname,
                     (int)process->retvalue.i,
                     (process->retvalue.i >= 0)?"success":"failure");
        }
        if(process->retvalue.i >= 0)
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
        char *pathname = tracee_strdup(tid, process->params[1].p);
        if(pathname[0] != '/')
        {
            char *oldpath = pathname;
            pathname = abspath(process->wd, oldpath);
            free(oldpath);
        }
        if(verbosity >= 3)
        {
            log_info("symlink(\"%s\") = %d (%s)", pathname,
                     (int)process->retvalue.i,
                     (process->retvalue.i >= 0)?"success":"failure");
        }
        if(process->retvalue.i >= 0)
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
        char *pathname = tracee_strdup(tid, process->params[0].p);
        if(pathname[0] != '/')
        {
            char *oldpath = pathname;
            pathname = abspath(process->wd, oldpath);
            free(oldpath);
        }
        if(verbosity >= 3)
        {
            log_info("chdir(\"%s\") = %d (%s)", pathname,
                     (int)process->retvalue.i,
                     (process->retvalue.i >= 0)?"success":"failure");
        }
        if(process->retvalue.i >= 0)
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
        execi->binary = tracee_strdup(tid, process->params[0].p);
        if(execi->binary[0] != '/')
        {
            char *oldbin = execi->binary;
            execi->binary = abspath(process->wd, oldbin);
            free(oldbin);
        }
        execi->argv = tracee_strarraydup(tid, process->params[1].p);
        execi->envp = tracee_strarraydup(tid, process->params[2].p);
        if(verbosity >= 3)
        {
            log_info("execve called by %d:\n  binary=%s\n  argv:",
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
        struct Process *exec_process = process;
        struct ExecveInfo *execi = exec_process->syscall_info;
        if(execi == NULL)
        {
            /* On Linux, execve changes tid to the thread leader's tid, no
             * matter which thread made the call. This means that the process
             * that just returned from execve might not be the one which
             * called.
             * So we start by finding the one which called execve.
             * Possible confusion here if two threads call execve at the same
             * time, but that would be very bad code. */
            size_t i;
            for(i = 0; i < processes_size; ++i)
            {
                if(processes[i]->status == PROCESS_ATTACHED
                 && processes[i]->tgid == process->tgid
                 && processes[i]->in_syscall
                 && processes[i]->current_syscall == SYS_execve
                 && processes[i]->syscall_info != NULL)
                {
                    exec_process = processes[i];
                    break;
                }
            }
            if(exec_process == NULL)
            {
                log_critical("process %d completing execve() but call wasn't "
                             "recorded", tid);
                return -1;
            }
            execi = exec_process->syscall_info;

            /* The process that called execve() disappears without any trace */
            if(db_add_exit(exec_process->identifier, 0) != 0)
                return -1;
            free(exec_process->wd);
            exec_process->status = PROCESS_FREE;
        }
        if(process->retvalue.i >= 0)
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
            /* Note that here, the database records that the thread leader
             * called execve, instead of thread exec_process->tid. */
            if(verbosity >= 2)
                log_info("Proc %d successfully exec'd %s",
                         exec_process->tid, execi->binary);
            /* Process will get SIGTRAP with PTRACE_EVENT_EXEC */
            if(trace_add_files_from_proc(process->identifier, process->tid,
                                         execi->binary) != 0)
                return -1;
        }

        free_strarray(execi->argv);
        free_strarray(execi->envp);
        free(execi->binary);
        free(execi);
        exec_process->syscall_info = NULL;
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
        if(process->retvalue.i > 0)
        {
            int is_thread = 0;
            pid_t new_tid = process->retvalue.i;
            struct Process *new_process;
            if(syscall == SYS_clone)
                is_thread = process->params[0].u & CLONE_THREAD;
            if(verbosity >= 2)
                log_info("Process %d created by %d via %s\n"
                         "    (thread: %s) (working directory: %s)",
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
                    log_critical("just created process that is already "
                                 "running (status=%d)", new_process->status);
                    return -1;
                }
                new_process->status = PROCESS_ATTACHED;
                ptrace(PTRACE_SYSCALL, new_process->tid, NULL, NULL);
                if(verbosity >= 2)
                {
                    unsigned int nproc, unknown;
                    trace_count_processes(&nproc, &unknown);
                    log_info("%d processes (inc. %d unattached)",
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
    else if(verbosity >= 1 && process->in_syscall && process->retvalue.i >= 0
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
        void *arg1;
        void *arg2;
#ifdef SYS_socketcall
        if(syscall == SYS_socketcall)
        {
            arg1 = process->params[2].p;
            arg2 = process->params[3].p;
        }
        else
#endif
        {
            arg1 = process->params[1].p;
            arg2 = process->params[2].p;
        }
        tracee_read(tid, (void*)&addrlen, arg2, sizeof(addrlen));
        if(addrlen >= sizeof(short))
        {
            void *address = malloc(addrlen);
            tracee_read(tid, address, arg1, addrlen);
            log_warn_("process accepted a connection from ");
            print_sockaddr(stderr, address, addrlen);
            fprintf(stderr, "\n");
            free(address);
        }
    }
    else if(verbosity >= 1 && process->in_syscall && process->retvalue.i >= 0
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
        void *arg1;
#ifdef SYS_socketcall
        if(syscall == SYS_socketcall)
        {
             arg1 = process->params[2].p;
             addrlen = process->params[3].u;
        }
        else
#endif
        {
             arg1 = process->params[1].p;
             addrlen = process->params[2].u;
        }
        if(addrlen >= sizeof(short))
        {
            void *address = malloc(addrlen);
            tracee_read(tid, address, arg1, addrlen);
            log_warn_("process connected to ");
            print_sockaddr(stderr, address, addrlen);
            fprintf(stderr, "\n");
            free(address);
        }
    }
    /* ********************
     * Other syscalls that might be of interest but that we don't handle yet
     */
    else if(verbosity >= 1 && process->in_syscall && process->retvalue.i >= 0)
    {
        char *desc = syscall_unhandled(syscall, process);
        if(desc != NULL)
        {
            log_warn("process %d used unhandled system call %s",
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
