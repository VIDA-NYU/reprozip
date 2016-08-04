#ifndef DATABASE_H
#define DATABASE_H

#define FILE_READ   0x01
#define FILE_WRITE  0x02
#define FILE_WDIR   0x04  /* File is used as a process's working dir */
#define FILE_STAT   0x08  /* File is stat()d (only metadata is read) */
#define FILE_LINK   0x10  /* The link itself is accessed, no dereference */

#define TYPE_REG    1
#define TYPE_DIR    2
#define TYPE_LINK   3

int db_init(const char *dirname);
int db_close(int rollback);
int db_add_process(unsigned int *id, unsigned int parent_id,
                   const char *working_dir, int is_thread);
int db_add_exit(unsigned int id, int exitcode, int cpu_time);
int db_add_first_process(unsigned int *id, const char *working_dir);
int db_add_file_open(unsigned int process,
                     const char *path, unsigned int mode);
int db_add_exec(unsigned int process, const char *binary,
                const char *const *argv, const char *const *envp,
                const char *workingdir);
int db_add_connection(unsigned int process, int inbound, const char *family,
                      const char *protocol, const char *address);

#endif
