#include <errno.h>
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
#ifndef SYS_CONNECT
#define SYS_CONNECT 3
#endif
#ifndef SYS_ACCEPT
#define SYS_ACCEPT 5
#endif


#define SYSCALL_I386        0
#define SYSCALL_X86_64      1
#define SYSCALL_X86_64_x32  2


struct syscall_table_entry {
    const char *name;
    int (*proc_entry)(const char*, struct Process *, unsigned int);
    int (*proc_exit)(const char*, struct Process *, unsigned int);
    unsigned int udata;
};

struct syscall_table {
    size_t length;
    struct syscall_table_entry *entries;
};

struct syscall_table *syscall_tables = NULL;


static char *abs_path_arg(const struct Process *process, size_t arg)
{
    char *pathname = tracee_strdup(process->tid, process->params[arg].p);
    if(pathname[0] != '/')
    {
        char *oldpath = pathname;
        pathname = abspath(process->threadgroup->wd, oldpath);
        free(oldpath);
    }
    return pathname;
}


static const char *print_sockaddr(void *address, socklen_t addrlen)
{
    static char buffer[512];
    const short family = ((struct sockaddr*)address)->sa_family;
    if(family == AF_INET && addrlen >= sizeof(struct sockaddr_in))
    {
        struct sockaddr_in *address_ = address;
        snprintf(buffer, 512, "%s:%d",
                inet_ntoa(address_->sin_addr),
                ntohs(address_->sin_port));
    }
    else if(family == AF_INET6
          && addrlen >= sizeof(struct sockaddr_in6))
    {
        struct sockaddr_in6 *address_ = address;
        char buf[50];
        inet_ntop(AF_INET6, &address_->sin6_addr, buf, sizeof(buf));
        snprintf(buffer, 512, "[%s]:%d", buf, ntohs(address_->sin6_port));
    }
    else
        snprintf(buffer, 512, "<unknown destination, sa_family=%d>", family);
    return buffer;
}


/* ********************
 * Other syscalls that might be of interest but that we don't handle yet
 */

static int syscall_unhandled_path1(const char *name, struct Process *process,
                                   unsigned int udata)
{
    if(logging_level <= 30 && process->in_syscall && process->retvalue.i >= 0
     && name != NULL)
    {
        char *pathname = abs_path_arg(process, 0);
        log_info(process->tid, "process used unhandled system call %s(\"%s\")",
                 name, pathname);
        free(pathname);
    }
    return 0;
}

static int syscall_unhandled_other(const char *name, struct Process *process,
                                   unsigned int udata)
{
    if(process->in_syscall && process->retvalue.i >= 0 && name != NULL)
        log_info(process->tid, "process used unhandled system call %s", name);
    return 0;
}


/* ********************
 * open(), creat(), access()
 */

#define SYSCALL_OPENING_OPEN    1
#define SYSCALL_OPENING_ACCESS  2
#define SYSCALL_OPENING_CREAT   3

static int syscall_fileopening_in(const char *name, struct Process *process,
                                  unsigned int udata)
{
    unsigned int mode = flags2mode(process->params[1].u);
    if( (mode & FILE_READ) && (mode & FILE_WRITE) )
    {
        char *pathname = abs_path_arg(process, 0);
        if(access(pathname, F_OK) != 0 && errno == ENOENT)
        {
            log_debug(process->tid, "Doing RW open, file exists: no");
            process->flags &= ~PROCFLAG_OPEN_EXIST;
        }
        else
        {
            log_debug(process->tid, "Doing RW open, file exists: yes");
            process->flags |= PROCFLAG_OPEN_EXIST;
        }
        free(pathname);
    }
    return 0;
}

static int syscall_fileopening_out(const char *name, struct Process *process,
                                   unsigned int syscall)
{
    unsigned int mode;
    char *pathname = abs_path_arg(process, 0);

    if(syscall == SYSCALL_OPENING_ACCESS)
        mode = FILE_STAT;
    else if(syscall == SYSCALL_OPENING_CREAT)
        mode = flags2mode(process->params[1].u |
                          O_CREAT | O_WRONLY | O_TRUNC);
    else /* syscall == SYSCALL_OPENING_OPEN */
    {
        mode = flags2mode(process->params[1].u);
        if( (process->retvalue.i >= 0) /* Open succeeded */
         && (mode & FILE_READ) && (mode & FILE_WRITE) ) /* In readwrite mode */
        {
            /* But the file doesn't exist */
            if(!(process->flags & PROCFLAG_OPEN_EXIST))
                /* Consider this a simple write */
                mode &= ~FILE_READ;
        }
    }

    if(logging_level <= 10)
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

        if(syscall == SYSCALL_OPENING_OPEN)
            log_debug(process->tid,
                      "open(\"%s\", mode=%s) = %d (%s)",
                      pathname,
                      s_mode,
                      (int)process->retvalue.i,
                      (process->retvalue.i >= 0)?"success":"failure");
        else /* creat or access */
            log_debug(process->tid,
                      "%s(\"%s\") (mode=%s) = %d (%s)",
                      (syscall == SYSCALL_OPENING_OPEN)?"open":
                          (syscall == SYSCALL_OPENING_CREAT)?"creat":"access",
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
            return -1; /* LCOV_EXCL_LINE */
    }

    free(pathname);
    return 0;
}


/* ********************
 * rename(), link(), symlink()
 */

static int syscall_filecreating(const char *name, struct Process *process,
                                unsigned int is_symlink)
{
    if(process->retvalue.i >= 0)
    {
        char *written_path = abs_path_arg(process, 1);
        int is_dir = path_is_dir(written_path);
        /* symlink doesn't actually read the source */
        if(!is_symlink)
        {
            char *read_path = abs_path_arg(process, 0);
            if(db_add_file_open(process->identifier,
                                read_path,
                                FILE_READ | FILE_LINK,
                                is_dir) != 0)
                return -1; /* LCOV_EXCL_LINE */
            free(read_path);
        }
        if(db_add_file_open(process->identifier,
                            written_path,
                            FILE_WRITE | FILE_LINK,
                            is_dir) != 0)
            return -1; /* LCOV_EXCL_LINE */
        free(written_path);
    }
    return 0;
}

static int syscall_filecreating_at(const char *name, struct Process *process,
                                   unsigned int is_symlink)
{
    if(process->retvalue.i >= 0)
    {
        if( (process->params[0].i == AT_FDCWD)
         && (process->params[2].i == AT_FDCWD) )
        {
            char *written_path = abs_path_arg(process, 3);
            int is_dir = path_is_dir(written_path);
            /* symlink doesn't actually read the source */
            if(!is_symlink)
            {
                char *read_path = abs_path_arg(process, 1);
                if(db_add_file_open(process->identifier,
                                    read_path,
                                    FILE_READ | FILE_LINK,
                                    is_dir) != 0)
                    return -1; /* LCOV_EXCL_LINE */
                free(read_path);
            }
            if(db_add_file_open(process->identifier,
                                written_path,
                                FILE_WRITE | FILE_LINK,
                                is_dir) != 0)
                return -1; /* LCOV_EXCL_LINE */
            free(written_path);
        }
        else
            return syscall_unhandled_other(name, process, 0);
    }
    return 0;
}


/* ********************
 * stat(), lstat()
 */

static int syscall_filestat(const char *name, struct Process *process,
                            unsigned int no_deref)
{
    if(process->retvalue.i >= 0)
    {
        char *pathname = abs_path_arg(process, 0);
        if(db_add_file_open(process->identifier,
                            pathname,
                            FILE_STAT | (no_deref?FILE_LINK:0),
                            path_is_dir(pathname)) != 0)
            return -1; /* LCOV_EXCL_LINE */
        free(pathname);
    }
    return 0;
}


/* ********************
 * readlink()
 */

static int syscall_readlink(const char *name, struct Process *process,
                            unsigned int udata)
{
    if(process->retvalue.i >= 0)
    {
        char *pathname = abs_path_arg(process, 0);
        if(db_add_file_open(process->identifier,
                            pathname,
                            FILE_STAT | FILE_LINK,
                            0) != 0)
            return -1; /* LCOV_EXCL_LINE */
        free(pathname);
    }
    return 0;
}


/* ********************
 * mkdir()
 */

static int syscall_mkdir(const char *name, struct Process *process,
                         unsigned int udata)
{
    if(process->retvalue.i >= 0)
    {
        char *pathname = abs_path_arg(process, 0);
        log_debug(process->tid, "mkdir(\"%s\")", pathname);
        if(db_add_file_open(process->identifier,
                            pathname,
                            FILE_WRITE,
                            1) != 0)
            return -1; /* LCOV_EXCL_LINE */
        free(pathname);
    }
    return 0;
}


/* ********************
 * chdir()
 */

static int syscall_chdir(const char *name, struct Process *process,
                         unsigned int udata)
{
    if(process->retvalue.i >= 0)
    {
        char *pathname = abs_path_arg(process, 0);
        free(process->threadgroup->wd);
        process->threadgroup->wd = pathname;
        if(db_add_file_open(process->identifier,
                            pathname,
                            FILE_WDIR,
                            1) != 0)
            return -1; /* LCOV_EXCL_LINE */
    }
    return 0;
}


/* ********************
 * execve()
 *
 * See also special handling in syscall_handle() and PTRACE_EVENT_EXEC case
 * in trace().
 */

#define SHEBANG_MAX_LEN 128 /* = Linux's BINPRM_BUF_SIZE */

static int record_shebangs(struct Process *process, const char *exec_target)
{
    const char *wd = process->threadgroup->wd;
    char buffer[SHEBANG_MAX_LEN];
    char target_buffer[SHEBANG_MAX_LEN];
    int step;
    for(step = 0; step < 4; ++step)
    {
        FILE *execd = fopen(exec_target, "rb");
        size_t ret = 0;
        if(execd != NULL)
        {
            ret = fread(buffer, 1, SHEBANG_MAX_LEN - 1, execd);
            fclose(execd);
        }
        if(ret == 0)
        {
            log_error(process->tid, "couldn't open executed file %s", exec_target);
            return 0;
        }
        if(buffer[0] != '#' || buffer[1] != '!')
        {
            // Check if executable is set-uid or set-gid
            struct stat statbuf;
            if(stat(exec_target, &statbuf) != 0)
            {
                /* LCOV_EXCL_START : stat() shouldn't fail if fopen() above worked */
                log_error(process->tid, "couldn't stat executed file %s", exec_target);
                /* LCOV_EXCL_STOP */
            }
            else
            {
                if((statbuf.st_mode & 04000) == 04000)
                {
                    if(statbuf.st_uid != getuid())
                    {
                        log_warn(process->tid,
                                 "executing set-uid binary! For security, "
                                 "Linux will not give the process any "
                                 "privileges from set-uid while it is being "
                                 "traced. This will probably break whatever "
                                 "you are tracing. Executable: %s",
                                 exec_target);
                    }
                    else
                    {
                        log_info(process->tid,
                                 "binary has set-uid bit set, not a problem "
                                 "because it is owned by our user");
                    }
                }
                if((statbuf.st_mode & 02000) == 02000)
                {
                    int is_our_group = 0;
                    size_t i, size;
                    // Get the list of groups
                    gid_t *groups = NULL;
                    int ret = getgroups(0, NULL);
                    if(ret >= 0)
                    {
                        size = (size_t)ret;
                        groups = malloc(sizeof(gid_t) * size);
                        ret = getgroups(ret, groups);
                    }
                    if(ret < 0)
                    {
                        /* LCOV_EXCL_START : Shouldn't ever fail */
                        free(groups);
                        log_critical(process->tid, "getgroups() failed: %s",
                                     strerror(errno));
                        return -1;
                        /* LCOV_EXCL_STOP */
                    }

                    // Check if the gid is one of our groups
                    for(i = 0; i < size; ++i)
                    {
                        if(groups[i] == statbuf.st_gid)
                        {
                            is_our_group = 1;
                            break;
                        }
                    }
                    free(groups);

                    if(!is_our_group)
                    {
                        log_warn(process->tid,
                                 "executing set-gid binary! For security, "
                                 "Linux will not give the process any "
                                 "privileges from set-gid while it is being "
                                 "traced. This will probably break whatever "
                                 "you are tracing. Executable: %s",
                                 exec_target);
                    }
                    else
                    {
                        log_info(process->tid,
                                 "binary has set-gid bit set, not a problem "
                                 "because it is in one of our groups");
                    }
                }
            }
            return 0;
        }
        else
        {
            char *start = buffer + 2;
            buffer[ret] = '\0';
            while(*start == '\t' || *start == ' ')
                ++start;
            if(*start == '\n' || *start == '\0')
            {
                log_info(process->tid, "empty shebang in %s", exec_target);
                return 0;
            }
            {
                char *end = start;
                while(*end != '\t' && *end != ' ' &&
                      *end != '\n' && *end != '\0')
                    ++end;
                *end = '\0';
            }
            log_info(process->tid, "read shebang: %s -> %s", exec_target, start);
            if(*start != '/')
            {
                char *pathname = abspath(wd, start);
                if(db_add_file_open(process->identifier,
                                    pathname,
                                    FILE_READ,
                                    0) != 0)
                    return -1; /* LCOV_EXCL_LINE */
                free(pathname);
            }
            else
                if(db_add_file_open(process->identifier,
                                    start,
                                    FILE_READ,
                                    0) != 0)
                    return -1; /* LCOV_EXCL_LINE */
            exec_target = strcpy(target_buffer, start);
        }
    }
    log_error(process->tid, "reached maximum shebang depth");
    return 0;
}

static int syscall_execve_in(const char *name, struct Process *process,
                             unsigned int udata)
{
    /* int execve(const char *filename,
     *            char *const argv[],
     *            char *const envp[]); */
    struct ExecveInfo *execi = malloc(sizeof(struct ExecveInfo));
    execi->binary = abs_path_arg(process, 0);
    execi->argv = tracee_strarraydup(process->mode, process->tid,
                                     process->params[1].p);
    execi->envp = tracee_strarraydup(process->mode, process->tid,
                                     process->params[2].p);
    if(logging_level <= 10)
    {
        log_debug(process->tid, "execve called:\n  binary=%s\n  argv:",
                  execi->binary);
        {
            /* Note: this conversion is correct and shouldn't need a cast */
            const char *const *v = (const char* const*)execi->argv;
            while(*v)
            {
                log_debug(process->tid, "    %s", *v);
                ++v;
            }
        }
        {
            size_t nb = 0;
            while(execi->envp[nb] != NULL)
                ++nb;
            log_debug(process->tid, "  envp: (%u entries)", (unsigned int)nb);
        }
    }
    process->execve_info = execi;
    return 0;
}

int syscall_execve_event(struct Process *process)
{
    struct Process *exec_process = process;
    struct ExecveInfo *execi = exec_process->execve_info;
    if(execi == NULL)
    {
        /* On Linux, execve changes tid to the thread leader's tid, no
         * matter which thread made the call. This means that the process
         * that just returned from execve might not be the one which
         * called.
         * So we start by finding the one which called execve.
         * No possible confusion here since all other threads will have been
         * terminated by the kernel. */
        size_t i;
        for(i = 0; i < processes_size; ++i)
        {
            if(processes[i]->status == PROCSTAT_ATTACHED
             && processes[i]->threadgroup == process->threadgroup
             && processes[i]->in_syscall
             && processes[i]->execve_info != NULL)
            {
                exec_process = processes[i];
                break;
            }
        }
        if(exec_process == NULL)
        {
            /* LCOV_EXCL_START : internal error */
            log_critical(process->tid,
                         "execve() completed but call wasn't recorded");
            return -1;
            /* LCOV_EXCL_STOP */
        }
        execi = exec_process->execve_info;

        /* The process that called execve() disappears without any trace */
        if(db_add_exit(exec_process->identifier, 0) != 0)
            return -1; /* LCOV_EXCL_LINE */
        log_debug(exec_process->tid,
                  "original exec'ing thread removed, tgid: %d",
                  process->tid);
        exec_process->execve_info = NULL;
        trace_free_process(exec_process);
    }
    else
        exec_process->execve_info = NULL;

    process->flags = PROCFLAG_EXECD;

    /* Note: execi->argv needs a cast to suppress a bogus warning
     * While conversion from char** to const char** is invalid, conversion from
     * char** to const char*const* is, in fact, safe.
     * G++ accepts it, GCC issues a warning. */
    if(db_add_exec(process->identifier, execi->binary,
                   (const char *const*)execi->argv,
                   (const char *const*)execi->envp,
                   process->threadgroup->wd) != 0)
        return -1; /* LCOV_EXCL_LINE */
    /* Note that here, the database records that the thread leader called
     * execve, instead of thread exec_process->tid. */
    log_info(process->tid, "successfully exec'd %s", execi->binary);

    /* Follow shebangs */
    if(record_shebangs(process, execi->binary) != 0)
        return -1; /* LCOV_EXCL_LINE */

    if(trace_add_files_from_proc(process->identifier, process->tid,
                                 execi->binary) != 0)
        return -1; /* LCOV_EXCL_LINE */

    free_execve_info(execi);
    return 0;
}

static int syscall_execve_out(const char *name, struct Process *process,
                              unsigned int execve_syscall)
{
    log_debug(process->tid, "execve() failed");
    if(process->execve_info != NULL)
    {
        free_execve_info(process->execve_info);
        process->execve_info = NULL;
    }
    return 0;
}


/* ********************
 * fork(), clone(), ...
 */

static int syscall_fork_in(const char *name, struct Process *process,
                           unsigned int udata)
{
    process->flags |= PROCFLAG_FORKING;
    return 0;
}

static int syscall_fork_out(const char *name, struct Process *process,
                            unsigned int udata)
{
    process->flags &= ~PROCFLAG_FORKING;
    return 0;
}

int syscall_fork_event(struct Process *process, unsigned int event)
{
#ifndef CLONE_THREAD
#define CLONE_THREAD 0x00010000
#endif

    int is_thread = 0;
    struct Process *new_process;
    unsigned long new_tid;

    ptrace(PTRACE_GETEVENTMSG, process->tid, NULL, &new_tid);

    if( (process->flags & PROCFLAG_FORKING) == 0)
    {
        /* LCOV_EXCL_START : internal error */
        log_critical(process->tid,
                     "process created new process %d but we didn't see syscall "
                     "entry", new_tid);
        return -1;
        /* LCOV_EXCL_STOP */
    }
    else if(event == PTRACE_EVENT_CLONE)
        is_thread = process->params[0].u & CLONE_THREAD;
    process->flags &= ~PROCFLAG_FORKING;

    if(logging_level <= 20)
        log_info(new_tid, "process created by %d via %s\n"
                 "    (thread: %s) (working directory: %s)",
                 process->tid,
                 (event == PTRACE_EVENT_FORK)?"fork()":
                 (event == PTRACE_EVENT_VFORK)?"vfork()":
                 "clone()",
                 is_thread?"yes":"no",
                 process->threadgroup->wd);

    /* At this point, the process might have been seen by waitpid in trace() or
     * not */
    new_process = trace_find_process(new_tid);
    if(new_process != NULL)
    {
        /* Process has been seen before and options were set */
        if(new_process->status != PROCSTAT_UNKNOWN)
        {
            /* LCOV_EXCL_START: : internal error */
            log_critical(new_tid,
                         "just created process that is already running "
                         "(status=%d)", new_process->status);
            return -1;
            /* LCOV_EXCL_STOP */
        }
        new_process->status = PROCSTAT_ATTACHED;
        ptrace(PTRACE_SYSCALL, new_process->tid, NULL, NULL);
        if(logging_level <= 20)
        {
            unsigned int nproc, unknown;
            trace_count_processes(&nproc, &unknown);
            log_info(0, "%d processes (inc. %d unattached)",
                     nproc, unknown);
        }
    }
    else
    {
        /* Process hasn't been seen before (event happened first) */
        new_process = trace_get_empty_process();
        new_process->status = PROCSTAT_ALLOCATED;
        new_process->flags = 0;
        /* New process gets a SIGSTOP, but we resume on attach */
        new_process->tid = new_tid;
        new_process->in_syscall = 0;
    }

    if(is_thread)
    {
        new_process->threadgroup = process->threadgroup;
        process->threadgroup->refs++;
        log_debug(process->threadgroup->tgid, "threadgroup refs=%d",
                  process->threadgroup->refs);
    }
    else
        new_process->threadgroup = trace_new_threadgroup(
                new_process->tid,
                strdup(process->threadgroup->wd));

    /* Parent will also get a SIGTRAP with PTRACE_EVENT_FORK */

    if(db_add_process(&new_process->identifier,
                      process->identifier,
                      process->threadgroup->wd, is_thread) != 0)
        return -1; /* LCOV_EXCL_LINE */

    return 0;
}


/* ********************
 * Network connections
 */

static int handle_accept(struct Process *process,
                         void *arg1, void *arg2)
{
    socklen_t addrlen;
    tracee_read(process->tid, (void*)&addrlen, arg2, sizeof(addrlen));
    if(addrlen >= sizeof(short))
    {
        void *address = malloc(addrlen);
        tracee_read(process->tid, address, arg1, addrlen);
        log_info(process->tid, "process accepted a connection from %s",
                 print_sockaddr(address, addrlen));
        free(address);
    }
    return 0;
}

static int handle_connect(struct Process *process,
                          void *arg1, socklen_t addrlen)
{
    if(addrlen >= sizeof(short))
    {
        void *address = malloc(addrlen);
        tracee_read(process->tid, address, arg1, addrlen);
        log_info(process->tid, "process connected to %s",
                 print_sockaddr(address, addrlen));
        free(address);
    }
    return 0;
}

static int syscall_socketcall(const char *name, struct Process *process,
                              unsigned int udata)
{
    if(process->retvalue.i >= 0)
    {
        /* Argument 1 is an array of longs, which are either numbers of pointers */
        uint64_t args = process->params[1].u;
        /* Size of each element in the array */
        const size_t wordsize = tracee_getwordsize(process->mode);
        /* Note that void* pointer arithmetic is illegal, hence the uint */
        if(process->params[0].u == SYS_ACCEPT)
            return handle_accept(process,
                                 tracee_getptr(process->mode, process->tid,
                                               (void*)(args + 1*wordsize)),
                                 tracee_getptr(process->mode, process->tid,
                                               (void*)(args + 2*wordsize)));
        else if(process->params[0].u == SYS_CONNECT)
            return handle_connect(process,
                                  tracee_getptr(process->mode, process->tid,
                                                (void*)(args + 1*wordsize)),
                                  tracee_getlong(process->mode, process->tid,
                                                 (void*)(args + 2*wordsize)));
    }
    return 0;
}

static int syscall_accept(const char *name, struct Process *process,
                          unsigned int udata)
{
    if(process->retvalue.i >= 0)
        return handle_accept(process,
                             process->params[1].p, process->params[2].p);
    else
        return 0;
}

static int syscall_connect(const char *name, struct Process *process,
                           unsigned int udata)
{
    if(process->retvalue.i >= 0)
        return handle_connect(process,
                              process->params[1].p, process->params[2].u);
    else
        return 0;
}


/* ********************
 * *at variants, handled if dirfd is AT_FDCWD
 */
static int syscall_xxx_at(const char *name, struct Process *process,
                          unsigned int real_syscall)
{
    /* Argument 0 is a file descriptor, we assume that the rest of them match
     * the non-at variant of the syscall */
    /* It seems that Linux accepts both AT_FDCWD=-100 sign-extended to 32 bit
     * and 64 bit. This is weird, but a process is unlikely to have 2**32 open
     * file descriptors anyway, so we only check bottom 32 bits. See #293 */
    if((int32_t)(process->params[0].u & 0xFFFFFFFF) == AT_FDCWD)
    {
        struct syscall_table_entry *entry = NULL;
        struct syscall_table *tbl;
        size_t syscall_type;
        if(process->mode == MODE_I386)
            syscall_type = SYSCALL_I386;
        else if(process->current_syscall & __X32_SYSCALL_BIT)
            syscall_type = SYSCALL_X86_64_x32;
        else
            syscall_type = SYSCALL_X86_64;
        tbl = &syscall_tables[syscall_type];
        if(real_syscall < tbl->length)
            entry = &tbl->entries[real_syscall];
        if(entry == NULL || entry->name == NULL)
        {
            /* LCOV_EXCL_START : Internal error, our syscall table is broken */
            log_critical(process->tid, "INVALID SYSCALL in *at dispatch: %d",
                         real_syscall);
            return 0;
            /* LCOV_EXCL_STOP */
        }
        else
        {
            int ret = 0;
            /* Shifts arguments */
            size_t i;
            register_type arg0 = process->params[0];
            for(i = 0; i < PROCESS_ARGS - 1; ++i)
                process->params[i] = process->params[i + 1];
            if(!process->in_syscall && entry->proc_entry)
                ret = entry->proc_entry(name, process, entry->udata);
            else if(process->in_syscall && entry->proc_exit)
                ret = entry->proc_exit(name, process, entry->udata);
            for(i = PROCESS_ARGS; i > 1; --i)
                process->params[i - 1] = process->params[i - 2];
            process->params[0] = arg0;
            return ret;
        }
    }
    else if(!process->in_syscall)
    {
        char *pathname = tracee_strdup(process->tid, process->params[1].p);
        log_info(process->tid,
                 "process used unhandled system call %s(%d, \"%s\")",
                 name, process->params[0].i, pathname);
        free(pathname);
    }
    return 0;
}


/* ********************
 * Building the syscall table
 */

struct unprocessed_table_entry {
    unsigned int n;
    const char *name;
    int (*proc_entry)(const char*, struct Process *, unsigned int);
    int (*proc_exit)(const char*, struct Process *, unsigned int);
    unsigned int udata;

};

struct syscall_table *process_table(struct syscall_table *table,
                                    const struct unprocessed_table_entry *orig)
{
    size_t i, length = 0;
    const struct unprocessed_table_entry *pos;

    /* Measure required table */
    pos = orig;
    while(pos->proc_entry || pos->proc_exit)
    {
        if(pos->n + 1 > length)
            length = pos->n + 1;
        ++pos;
    }

    /* Allocate table */
    table->length = length;
    table->entries = malloc(sizeof(struct syscall_table_entry) * length);

    /* Initialize to NULL */
    for(i = 0; i < length; ++i)
    {
        table->entries[i].name = NULL;
        table->entries[i].proc_entry = NULL;
        table->entries[i].proc_exit = NULL;
    }

    /* Copy from unordered list */
    {
        pos = orig;
        while(pos->proc_entry || pos->proc_exit)
        {
            table->entries[pos->n].name = pos->name;
            table->entries[pos->n].proc_entry = pos->proc_entry;
            table->entries[pos->n].proc_exit = pos->proc_exit;
            table->entries[pos->n].udata = pos->udata;
            ++pos;
        }
    }

    return table;
}

void syscall_build_table(void)
{
    if(syscall_tables != NULL)
        return ;

#if defined(I386)
    syscall_tables = malloc(1 * sizeof(struct syscall_table));
#elif defined(X86_64)
    syscall_tables = malloc(3 * sizeof(struct syscall_table));
#else
#   error Unrecognized architecture!
#endif

    /* i386 */
    {
        struct unprocessed_table_entry list[] = {
            {  5, "open", syscall_fileopening_in, syscall_fileopening_out,
                     SYSCALL_OPENING_OPEN},
            {  8, "creat", NULL, syscall_fileopening_out, SYSCALL_OPENING_CREAT},
            { 33, "access", NULL, syscall_fileopening_out, SYSCALL_OPENING_ACCESS},

            {106, "stat", NULL, syscall_filestat, 0},
            {107, "lstat", NULL, syscall_filestat, 1},
            {195, "stat64", NULL, syscall_filestat, 0},
            { 18, "oldstat", NULL, syscall_filestat, 0},
            {196, "lstat64", NULL, syscall_filestat, 1},
            { 84, "oldlstat", NULL, syscall_filestat, 1},

            { 85, "readlink", NULL, syscall_readlink, 0},

            { 39, "mkdir", NULL, syscall_mkdir, 0},

            { 12, "chdir", NULL, syscall_chdir, 0},

            { 11, "execve", syscall_execve_in, syscall_execve_out, 11},

            {  2, "fork", syscall_fork_in, syscall_fork_out, 0},
            {190, "vfork", syscall_fork_in, syscall_fork_out, 0},
            {120, "clone", syscall_fork_in, syscall_fork_out, 0},

            {102, "socketcall", NULL, syscall_socketcall, 0},

            /* File-creating syscalls: created path is second argument */
            { 38, "rename", NULL, syscall_filecreating, 0},
            {  9, "link", NULL, syscall_filecreating, 0},
            { 83, "symlink", NULL, syscall_filecreating, 1},

            /* File-creating syscalls, at variants: unhandled if first or third
             * argument is not AT_FDCWD, second is read, fourth is created */
            {302, "renameat", NULL, syscall_filecreating_at, 0},
            {303, "linkat", NULL, syscall_filecreating_at, 0},
            {304, "symlinkat", NULL, syscall_filecreating_at, 1},

            /* Half-implemented: *at() variants, when dirfd is AT_FDCWD */
            {296, "mkdirat", NULL, syscall_xxx_at, 39},
            {295, "openat", syscall_xxx_at, syscall_xxx_at, 5},
            {307, "faccessat", NULL, syscall_xxx_at, 33},
            {305, "readlinkat", NULL, syscall_xxx_at, 85},
            {300, "fstatat64", NULL, syscall_xxx_at, 195},

            /* Unhandled with path as first argument */
            { 40, "rmdir", NULL, syscall_unhandled_path1, 0},
            { 92, "truncate", NULL, syscall_unhandled_path1, 0},
            {193, "truncate64", NULL, syscall_unhandled_path1, 0},
            { 10, "unlink", NULL, syscall_unhandled_path1, 0},
            { 15, "chmod", NULL, syscall_unhandled_path1, 0},
            {182, "chown", NULL, syscall_unhandled_path1, 0},
            {212, "chown32", NULL, syscall_unhandled_path1, 0},
            { 16, "lchown", NULL, syscall_unhandled_path1, 0},
            {198, "lchown32", NULL, syscall_unhandled_path1, 0},
            { 30, "utime", NULL, syscall_unhandled_path1, 0},
            {271, "utimes", NULL, syscall_unhandled_path1, 0},
            {277, "mq_open", NULL, syscall_unhandled_path1, 0},
            {278, "mq_unlink", NULL, syscall_unhandled_path1, 0},

            /* Unhandled which use open descriptors */
            {301, "unlinkat", NULL, syscall_unhandled_other, 0},
            {306, "fchmodat", NULL, syscall_unhandled_other, 0},
            {298, "fchownat", NULL, syscall_unhandled_other, 0},

            /* Other unhandled */
            { 26, "ptrace", NULL, syscall_unhandled_other, 0},
            {341, "name_to_handle_at", NULL, syscall_unhandled_other, 0},

            /* Sentinel */
            {0, NULL, NULL, NULL, 0}
        };
        process_table(&syscall_tables[SYSCALL_I386], list);
    }

#ifdef X86_64
    /* x64 */
    {
        struct unprocessed_table_entry list[] = {
            {  2, "open", syscall_fileopening_in, syscall_fileopening_out,
                     SYSCALL_OPENING_OPEN},
            { 85, "creat", NULL, syscall_fileopening_out, SYSCALL_OPENING_CREAT},
            { 21, "access", NULL, syscall_fileopening_out, SYSCALL_OPENING_ACCESS},

            {  4, "stat", NULL, syscall_filestat, 0},
            {  6, "lstat", NULL, syscall_filestat, 1},

            { 89, "readlink", NULL, syscall_readlink, 0},

            { 83, "mkdir", NULL, syscall_mkdir, 0},

            { 80, "chdir", NULL, syscall_chdir, 0},

            { 59, "execve", syscall_execve_in, syscall_execve_out, 59},

            { 57, "fork", syscall_fork_in, syscall_fork_out, 0},
            { 58, "vfork", syscall_fork_in, syscall_fork_out, 0},
            { 56, "clone", syscall_fork_in, syscall_fork_out, 0},

            { 43, "accept", NULL, syscall_accept, 0},
            {288, "accept4", NULL, syscall_accept, 0},
            { 42, "connect", NULL, syscall_connect, 0},

            /* File-creating syscalls: created path is second argument */
            { 82, "rename", NULL, syscall_filecreating, 0},
            { 86, "link", NULL, syscall_filecreating, 0},
            { 88, "symlink", NULL, syscall_filecreating, 1},

            /* File-creating syscalls, at variants: unhandled if first or third
             * argument is not AT_FDCWD, second is read, fourth is created */
            {264, "renameat", NULL, syscall_filecreating_at, 0},
            {265, "linkat", NULL, syscall_filecreating_at, 0},
            {266, "symlinkat", NULL, syscall_filecreating_at, 1},

            /* Half-implemented: *at() variants, when dirfd is AT_FDCWD */
            {258, "mkdirat", NULL, syscall_xxx_at, 83},
            {257, "openat", syscall_xxx_at, syscall_xxx_at, 2},
            {269, "faccessat", NULL, syscall_xxx_at, 21},
            {267, "readlinkat", NULL, syscall_xxx_at, 89},
            {262, "newfstatat", NULL, syscall_xxx_at, 4},

            /* Unhandled with path as first argument */
            { 84, "rmdir", NULL, syscall_unhandled_path1, 0},
            { 76, "truncate", NULL, syscall_unhandled_path1, 0},
            { 87, "unlink", NULL, syscall_unhandled_path1, 0},
            { 90, "chmod", NULL, syscall_unhandled_path1, 0},
            { 92, "chown", NULL, syscall_unhandled_path1, 0},
            { 94, "lchown", NULL, syscall_unhandled_path1, 0},
            {132, "utime", NULL, syscall_unhandled_path1, 0},
            {235, "utimes", NULL, syscall_unhandled_path1, 0},
            {240, "mq_open", NULL, syscall_unhandled_path1, 0},
            {241, "mq_unlink", NULL, syscall_unhandled_path1, 0},

            /* Unhandled which use open descriptors */
            {263, "unlinkat", NULL, syscall_unhandled_other, 0},
            {268, "fchmodat", NULL, syscall_unhandled_other, 0},
            {260, "fchownat", NULL, syscall_unhandled_other, 0},

            /* Other unhandled */
            {101, "ptrace", NULL, syscall_unhandled_other, 0},
            {303, "name_to_handle_at", NULL, syscall_unhandled_other, 0},

            /* Sentinel */
            {0, NULL, NULL, NULL, 0}
        };
        process_table(&syscall_tables[SYSCALL_X86_64], list);
    }

    /* x32 */
    {
        struct unprocessed_table_entry list[] = {
            {  2, "open", syscall_fileopening_in, syscall_fileopening_out,
                     SYSCALL_OPENING_OPEN},
            { 85, "creat", NULL, syscall_fileopening_out, SYSCALL_OPENING_CREAT},
            { 21, "access", NULL, syscall_fileopening_out, SYSCALL_OPENING_ACCESS},

            {  4, "stat", NULL, syscall_filestat, 0},
            {  6, "lstat", NULL, syscall_filestat, 1},

            { 89, "readlink", NULL, syscall_readlink, 0},

            { 83, "mkdir", NULL, syscall_mkdir, 0},

            { 80, "chdir", NULL, syscall_chdir, 0},

            {520, "execve", syscall_execve_in, syscall_execve_out,
                     __X32_SYSCALL_BIT + 520},

            { 57, "fork", syscall_fork_in, syscall_fork_out, 0},
            { 58, "vfork", syscall_fork_in, syscall_fork_out, 0},
            { 56, "clone", syscall_fork_in, syscall_fork_out, 0},

            { 43, "accept", NULL, syscall_accept, 0},
            {288, "accept4", NULL, syscall_accept, 0},
            { 42, "connect", NULL, syscall_connect, 0},

            /* File-creating syscalls: created path is second argument */
            { 82, "rename", NULL, syscall_filecreating, 0},
            { 86, "link", NULL, syscall_filecreating, 0},
            { 88, "symlink", NULL, syscall_filecreating, 1},

            /* File-creating syscalls, at variants: unhandled if first or third
             * argument is not AT_FDCWD, second is read, fourth is created */
            {264, "renameat", NULL, syscall_filecreating_at, 0},
            {265, "linkat", NULL, syscall_filecreating_at, 0},
            {266, "symlinkat", NULL, syscall_filecreating_at, 1},

            /* Half-implemented: *at() variants, when dirfd is AT_FDCWD */
            {258, "mkdirat", NULL, syscall_xxx_at, 83},
            {257, "openat", syscall_xxx_at, syscall_xxx_at, 2},
            {269, "faccessat", NULL, syscall_xxx_at, 21},
            {267, "readlinkat", NULL, syscall_xxx_at, 89},
            {262, "newfstatat", NULL, syscall_xxx_at, 4},

            /* Unhandled with path as first argument */
            { 84, "rmdir", NULL, syscall_unhandled_path1, 0},
            { 76, "truncate", NULL, syscall_unhandled_path1, 0},
            { 87, "unlink", NULL, syscall_unhandled_path1, 0},
            { 90, "chmod", NULL, syscall_unhandled_path1, 0},
            { 92, "chown", NULL, syscall_unhandled_path1, 0},
            { 94, "lchown", NULL, syscall_unhandled_path1, 0},
            {132, "utime", NULL, syscall_unhandled_path1, 0},
            {235, "utimes", NULL, syscall_unhandled_path1, 0},
            {240, "mq_open", NULL, syscall_unhandled_path1, 0},
            {241, "mq_unlink", NULL, syscall_unhandled_path1, 0},

            /* Unhandled which use open descriptors */
            {263, "unlinkat", NULL, syscall_unhandled_other, 0},
            {268, "fchmodat", NULL, syscall_unhandled_other, 0},
            {260, "fchownat", NULL, syscall_unhandled_other, 0},

            /* Other unhandled */
            {521, "ptrace", NULL, syscall_unhandled_other, 0},
            {303, "name_to_handle_at", NULL, syscall_unhandled_other, 0},

            /* Sentinel */
            {0, NULL, NULL, NULL, 0}
        };
        process_table(&syscall_tables[SYSCALL_X86_64_x32], list);
    }
#endif
}


/* ********************
 * Handle a syscall via the table
 */

int syscall_handle(struct Process *process)
{
    pid_t tid = process->tid;
    const int syscall = process->current_syscall & ~__X32_SYSCALL_BIT;
    size_t syscall_type;
    const char *inout = process->in_syscall?"out":"in";
    if(process->mode == MODE_I386)
    {
        syscall_type = SYSCALL_I386;
        if(logging_level <= 5)
            log_debug(process->tid, "syscall %d (i386) (%s)", syscall, inout);
    }
    else if(process->current_syscall & __X32_SYSCALL_BIT)
    {
        /* LCOV_EXCL_START : x32 is not supported right now */
        syscall_type = SYSCALL_X86_64_x32;
        if(logging_level <= 5)
            log_debug(process->tid, "syscall %d (x32) (%s)", syscall, inout);
        /* LCOV_EXCL_STOP */
    }
    else
    {
        syscall_type = SYSCALL_X86_64;
        if(logging_level <= 5)
            log_debug(process->tid, "syscall %d (x64) (%s)", syscall, inout);
    }

    if(process->flags & PROCFLAG_EXECD)
    {
        if(logging_level <= 5)
            log_debug(process->tid,
                      "ignoring, EXEC'D is set -- just post-exec syscall-"
                      "return stop");
        process->flags &= ~PROCFLAG_EXECD;
        if(process->execve_info != NULL)
        {
            free_execve_info(process->execve_info);
            process->execve_info = NULL;
        }
        process->in_syscall = 1; /* set to 0 before function returns */
    }
    else
    {
        struct syscall_table_entry *entry = NULL;
        struct syscall_table *tbl = &syscall_tables[syscall_type];
        if(syscall < 0 || syscall >= 2000)
            /* LCOV_EXCL_START : internal error */
            log_error(process->tid, "INVALID SYSCALL %d", syscall);
            /* LCOV_EXCL_STOP */
        if(entry == NULL && syscall >= 0 && (size_t)syscall < tbl->length)
            entry = &tbl->entries[syscall];
        if(entry != NULL)
        {
            int ret = 0;
            if(entry->name)
                log_debug(process->tid, "%s()", entry->name);
            if(!process->in_syscall && entry->proc_entry)
                ret = entry->proc_entry(entry->name, process, entry->udata);
            else if(process->in_syscall && entry->proc_exit)
                ret = entry->proc_exit(entry->name, process, entry->udata);
            if(ret != 0)
                return -1;
        }
    }

    /* Run to next syscall */
    if(process->in_syscall)
    {
        process->in_syscall = 0;
        if(process->execve_info != NULL)
        {
            /* LCOV_EXCL_START : internal error */
            log_error(process->tid, "out of syscall with execve_info != NULL");
            return -1;
            /* LCOV_EXCL_STOP */

        }
        process->current_syscall = -1;
    }
    else
        process->in_syscall = 1;
    ptrace(PTRACE_SYSCALL, tid, NULL, NULL);

    return 0;
}
