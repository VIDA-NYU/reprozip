#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <sys/stat.h>

#include <sqlite3.h>

#include "database.h"
#include "hash.h"
#include "log.h"
#include "utils.h"

#define CHUNK_SIZE 4096

#define count(x) (sizeof((x))/sizeof(*(x)))
#define check(r) do { if((r) != SQLITE_OK) { goto sqlerror; } } while(0)

static sqlite3_uint64 gettime(void)
{
    sqlite3_uint64 timestamp;
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC, &now) == -1)
    {
        /* LCOV_EXCL_START : clock_gettime() is unlikely to fail */
        log_critical(0, "getting time failed (clock_gettime): %s",
                     strerror(errno));
        exit(1);
        /* LCOV_EXCL_END */
    }
    timestamp = now.tv_sec;
    timestamp *= 1000000000;
    timestamp += now.tv_nsec;
    return timestamp;
}

static sqlite3 *db;
static sqlite3_stmt *stmt_insert_process;
static sqlite3_stmt *stmt_set_exitcode;
static sqlite3_stmt *stmt_file_in_run;
static sqlite3_stmt *stmt_insert_file;
static sqlite3_stmt *stmt_insert_argv;
static sqlite3_stmt *stmt_insert_envp;
static sqlite3_stmt *stmt_insert_connection;

static int run_id = -1;
static const char *database_dir = NULL;

int db_init(const char *dirname)
{
    int tables_exist;

    char *filename = malloc(strlen(dirname) + 15);
    snprintf(filename, 15, "%s/trace.sqlite3", dirname);
    {
        int ret = sqlite3_open(filename, &db);
        free(filename);
        check(ret);
    }
    log_debug(0, "database file opened: %s", filename);
    database_dir = dirname;

    {
        size_t len = strlen(database_dir) + 6;
        char *filename = malloc(len + 1);
        assert(snprintf(filename, len + 1, "%s/files", database_dir) == len);
        mkdir(filename, 0777);
        free(filename);
    }

    check(sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL));

    {
        int ret;
        const char *sql = ""
                "SELECT name FROM SQLITE_MASTER "
                "WHERE type='table';";
        sqlite3_stmt *stmt_get_tables;
        unsigned int found = 0x00;
        check(sqlite3_prepare_v2(db, sql, -1, &stmt_get_tables, NULL));
        while((ret = sqlite3_step(stmt_get_tables)) == SQLITE_ROW)
        {
            const char *colname = (const char*)sqlite3_column_text(
                    stmt_get_tables, 0);
            if(strcmp("runs", colname) == 0)
                found |= 0x01;
            else if(strcmp("processes", colname) == 0)
                found |= 0x02;
            else if(strcmp("file_accesses", colname) == 0)
                found |= 0x04;
            else if(strcmp("files", colname) == 0)
                found |= 0x08;
            else if(strcmp("argv", colname) == 0)
                found |= 0x10;
            else if(strcmp("envp", colname) == 0)
                found |= 0x20;
            else if(strcmp("connections", colname) == 0)
                found |= 0x40;
            else
                goto wrongschema;
        }
        if(found == 0x00)
            tables_exist = 0;
        else if(found == 0x7F)
            tables_exist = 1;
        else
        {
        wrongschema:
            log_critical(0, "database schema is wrong");
            return -1;
        }
        sqlite3_finalize(stmt_get_tables);
        if(ret != SQLITE_DONE)
            goto sqlerror;
    }

    if(!tables_exist)
    {
        const char *sql[] = {
            "CREATE TABLE runs("
            "    id INTEGER NOT NULL PRIMARY KEY,"
            "    comment TEXT NULL"
            "    );",
            "CREATE TABLE processes("
            "    id INTEGER NOT NULL PRIMARY KEY,"
            "    run_id INTEGER NOT NULL,"
            "    parent INTEGER NULL,"
            "    timestamp INTEGER NOT NULL,"
            "    exit_timestamp INTEGER NULL,"
            "    cpu_time INTEGER NULL,"
            "    is_thread BOOLEAN NOT NULL,"
            "    exitcode INTEGER NULL"
            "    );",
            "CREATE TABLE files("
            "    id INTEGER NOT NULL PRIMARY KEY,"
            "    run_id INTEGER NOT NULL,"
            "    path TEXT NOT NULL,"
            "    timestamp INTEGER NOT NULL,"
            "    process INTEGER NOT NULL,"
            "    what INTEGER NOT NULL,"
            "    working_dir TEXT NULL,"
            "    permissions INTEGER NOT NULL,"
            "    uid INTEGER NOT NULL,"
            "    gid INTEGER NOT NULL,"
            "    type INTEGER NOT NULL,"
            "    data TEXT NULL"
            "    );",
            "CREATE TABLE argv("
            "    file INTEGER NOT NULL,"
            "    nb INTEGER NOT NULL,"
            "    value TEXT NOT NULL"
            "    );",
            "CREATE TABLE envp("
            "    file INTEGER NOT NULL,"
            "    name TEXT NOT NULL,"
            "    value TEXT NOT NULL"
            "    );",
            "CREATE TABLE connections("
            "    id INTEGER NOT NULL PRIMARY KEY,"
            "    process INTEGER NOT NULL,"
            "    timestamp INTEGER NOT NULL,"
            "    inbound INTEGER NOT NULL,"
            "    family TEXT NULL,"
            "    protocol TEXT NULL,"
            "    address TEXT NULL"
            "    );",
        };
        size_t i;
        for(i = 0; i < count(sql); ++i)
            check(sqlite3_exec(db, sql[i], NULL, NULL, NULL));
    }

    /* Create the run */
    {
        const char *sql = "INSERT INTO runs DEFAULT VALUES;";
        check(sqlite3_exec(db, sql, NULL, NULL, NULL));
        run_id = sqlite3_last_insert_rowid(db);
    }
    log_debug(0, "Created run %d", run_id);

    {
        const char *sql = ""
                "INSERT INTO processes(run_id, parent, timestamp, is_thread) "
                "VALUES(?, ?, ?, ?)";
        check(sqlite3_prepare_v2(db, sql, -1, &stmt_insert_process, NULL));
    }

    {
        const char *sql = ""
                "UPDATE processes SET exitcode=?, exit_timestamp=?, "
                "        cpu_time=? "
                "WHERE id=?";
        check(sqlite3_prepare_v2(db, sql, -1, &stmt_set_exitcode, NULL));
    }

    {
        const char *sql = ""
                "SELECT id FROM file_accesses"
                "WHERE path=? AND run_id=?";
        check(sqlite3_prepare_v2(db, sql, -1, &stmt_file_in_run, NULL));
    }

    {
        const char *sql = ""
                "INSERT INTO files(run_id, path, timestamp, process, what, "
                "        working_dir, permissions, uid, gid, type, data) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        check(sqlite3_prepare_v2(db, sql, -1, &stmt_insert_file, NULL));
    }

    {
        const char *sql = ""
                "INSERT INTO argv(file, nb, value) "
                "VALUES(?, ?, ?)";
        check(sqlite3_prepare_v2(db, sql, -1, &stmt_insert_argv, NULL));
    }

    {
        const char *sql = ""
                "INSERT INTO envp(file, name, value) "
                "VALUES(?, ?, ?)";
        check(sqlite3_prepare_v2(db, sql, -1, &stmt_insert_envp, NULL));
    }

    {
        const char *sql = ""
                "INSERT INTO connections(run_id, timestamp, process, "
                "        inbound, family, protocol, address) "
                "VALUES(?, ?, ?, ?, ?, ?, ?)";
        check(sqlite3_prepare_v2(db, sql, -1, &stmt_insert_connection, NULL));
    }

    return 0;

sqlerror:
    log_critical(0, "sqlite3 error creating database: %s", sqlite3_errmsg(db));
    return -1;
}

int db_close(int rollback)
{
    if(rollback)
        check(sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL));
    else
        check(sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL));
    log_debug(0, "database file closed%s", rollback?" (rolled back)":"");
    check(sqlite3_finalize(stmt_insert_process));
    check(sqlite3_finalize(stmt_set_exitcode));
    check(sqlite3_finalize(stmt_file_in_run));
    check(sqlite3_finalize(stmt_insert_file));
    check(sqlite3_finalize(stmt_insert_argv));
    check(sqlite3_finalize(stmt_insert_envp));
    check(sqlite3_finalize(stmt_insert_connection));
    check(sqlite3_close(db));
    run_id = -1;
    return 0;

sqlerror:
    log_critical(0, "sqlite3 error on exit: %s", sqlite3_errmsg(db));
    return -1;
}

#define DB_NO_PARENT ((unsigned int)-2)

int db_add_process(unsigned int *id, unsigned int parent_id,
                   const char *working_dir, int is_thread)
{
    check(sqlite3_bind_int(stmt_insert_process, 1, run_id));
    if(parent_id == DB_NO_PARENT)
        check(sqlite3_bind_null(stmt_insert_process, 2));
    else
        check(sqlite3_bind_int(stmt_insert_process, 2, parent_id));
    /* This assumes that we won't go over 2^32 seconds (~135 years) */
    check(sqlite3_bind_int64(stmt_insert_process, 3, gettime()));
    check(sqlite3_bind_int(stmt_insert_process, 4, is_thread?1:0));

    if(sqlite3_step(stmt_insert_process) != SQLITE_DONE)
        goto sqlerror;
    sqlite3_reset(stmt_insert_process);

    /* Get id */
    *id = sqlite3_last_insert_rowid(db);

    return db_add_file_open(*id, working_dir, FILE_WDIR);

sqlerror:
    /* LCOV_EXCL_START : Insertions shouldn't fail */
    log_critical(0, "sqlite3 error inserting process: %s", sqlite3_errmsg(db));
    return -1;
    /* LCOV_EXCL_END */
}

int db_add_first_process(unsigned int *id, const char *working_dir)
{
    return db_add_process(id, DB_NO_PARENT, working_dir, 0);
}

int db_add_exit(unsigned int id, int exitcode, int cpu_time)
{
    check(sqlite3_bind_int(stmt_set_exitcode, 1, exitcode));
    check(sqlite3_bind_int64(stmt_set_exitcode, 2, gettime()));
    check(sqlite3_bind_int(stmt_set_exitcode, 3, cpu_time));
    check(sqlite3_bind_int(stmt_set_exitcode, 4, id));

    if(sqlite3_step(stmt_set_exitcode) != SQLITE_DONE)
        goto sqlerror;
    sqlite3_reset(stmt_set_exitcode);

    return 0;

sqlerror:
    /* LCOV_EXCL_START : Insertions shouldn't fail */
    log_critical(0, "sqlite3 error setting exitcode: %s", sqlite3_errmsg(db));
    return -1;
    /* LCOV_EXCL_END */
}

void store_file(const char *path, const char *hexdigest)
{
    FILE *orig, *stored;
    {
        const char *fmt = "%s/files/%.2s/%s";
        int len = strlen(database_dir) + 48;
        char *filename = malloc(len + 1); /* FIXME: stack alloc? */
        int ret = snprintf(filename, len + 1, fmt, database_dir,
                           hexdigest, hexdigest + 2);
        (void)ret; assert(ret == len);
        if(access(path, F_OK) != -1)
        {
            log_debug(0, "file content already stored %s %s",
                      path, hexdigest);
            free(filename);
            return;
        }
        {
            size_t len_prefix = strlen(database_dir) + 9;
            assert(filename[len_prefix] == '/');
            filename[len_prefix] = '\0';
            mkdir(filename, 0777); /* {database_dir}/files/00 */
            filename[len_prefix] = '/';
        }
        stored = fopen(path, "wb");
        free(filename);
    }

    orig = fopen(path, "rb");
    log_debug(0, "storing file content %s %s", path, hexdigest);

    {
        char buffer[CHUNK_SIZE];
        size_t len = fread(buffer, 1, CHUNK_SIZE, orig);
        fwrite(buffer, 1, CHUNK_SIZE, stored);
        while(len == CHUNK_SIZE)
        {
            len = fread(buffer, 1, CHUNK_SIZE, orig);
            fwrite(buffer, 1, CHUNK_SIZE, stored);
        }
    }
    fclose(stored);
    fclose(orig);
}

static int add_file_open(unsigned int process, const char *path,
                         unsigned int mode, const char *workingdir,
                         sqlite3_int64 *rowid)
{
    struct stat buf;
    if(lstat(path, &buf) != 0)
    {
        /* LCOV_EXCL_START : shouldn't happen because a traced process just
         * accessed it */
        log_error(0, "error stat()ing %s: %s", path, strerror(errno));
        return -1;
        /* LCOV_EXCL_END */
    }

    sqlite3_clear_bindings(stmt_insert_file);
    check(sqlite3_bind_int(stmt_insert_file, 1, run_id));
    check(sqlite3_bind_text(stmt_insert_file, 2, path,
                            -1, SQLITE_TRANSIENT));
    /* This assumes that we won't go over 2^32 seconds (~135 years) */
    check(sqlite3_bind_int64(stmt_insert_file, 3, gettime()));
    check(sqlite3_bind_int(stmt_insert_file, 4, process));
    check(sqlite3_bind_int(stmt_insert_file, 5, mode));
    if(workingdir != NULL)
        check(sqlite3_bind_text(stmt_insert_file, 6, workingdir,
                                -1, SQLITE_TRANSIENT));
    else
        check(sqlite3_bind_null(stmt_insert_file, 6));

    if(mode != FILE_WRITE)
    {
        /* Check if we already accessed it during this run */
        int file_in_run;
        check(sqlite3_bind_text(stmt_file_in_run, 1, path,
                                -1, SQLITE_TRANSIENT));
        check(sqlite3_bind_int(stmt_file_in_run, 2, run_id));
        if(sqlite3_step(stmt_file_in_run) != SQLITE_ROW)
            goto sqlerror;
        file_in_run = sqlite3_column_int(stmt_file_in_run, 0);
        if(sqlite3_step(stmt_file_in_run) != SQLITE_DONE)
            goto sqlerror;
        sqlite3_reset(stmt_file_in_run);

        if(file_in_run)
            log_debug(0, "file already stored %s", path);
        else
        {
            log_debug(0, "file accessed for the first time, storing: %s",
                      path);
            check(sqlite3_bind_int(stmt_insert_file, 7, buf.st_mode & 07777));
            check(sqlite3_bind_int(stmt_insert_file, 8, buf.st_uid));
            check(sqlite3_bind_int(stmt_insert_file, 9, buf.st_gid));
            if(S_ISLNK(buf.st_mode))
            {
                char *target = read_link(path);
                check(sqlite3_bind_int(stmt_insert_file, 10, TYPE_LINK));
                check(sqlite3_bind_text(stmt_insert_file, 11, target,
                                        -1, SQLITE_TRANSIENT));
            }
            else if(S_ISDIR(buf.st_mode))
                check(sqlite3_bind_int(stmt_insert_file, 10, TYPE_DIR));
            else if(S_ISREG(buf.st_mode))
            {
                char hexdigest[41];
                FILE *fp = fopen(path, "rb");
                int ret = hash_file(fp, hexdigest);
                fclose(fp);
                if(ret != 0)
                {
                    log_critical(0, "error hashing file %s", path);
                    return -1;
                }
                check(sqlite3_bind_text(stmt_insert_file, 11, hexdigest,
                                        40, SQLITE_TRANSIENT));
                check(sqlite3_bind_int(stmt_insert_file, 10, TYPE_REG));

                /* Copy the file to the store */
                store_file(path, hexdigest);
            }
            else
            {
                log_error(0, "error: don't know the type of %s", path);
                return 0;
            }
        }
    }

    if(sqlite3_step(stmt_insert_file) != SQLITE_DONE)
        goto sqlerror;
    if(rowid != NULL)
        *rowid = sqlite3_last_insert_rowid(db);
    sqlite3_reset(stmt_insert_file);
    return 0;

sqlerror:
    /* LCOV_EXCL_START : Insertions shouldn't fail */
    log_critical(0, "sqlite3 error inserting file: %s", sqlite3_errmsg(db));
    return -1;
    /* LCOV_EXCL_END */
}

int db_add_file_open(unsigned int process, const char *path,
                     unsigned int mode)
{
    return add_file_open(process, path, mode, NULL, NULL);
}

int db_add_exec(unsigned int process, const char *binary,
                const char *const *argv, const char *const *envp,
                const char *workingdir)
{
    size_t i;
    sqlite3_int64 rowid;
    if(add_file_open(process, binary, FILE_EXEC, workingdir, &rowid) != 0)
        return -1;

    check(sqlite3_bind_int(stmt_insert_argv, 1, rowid));
    for(i = 0; argv[i] != NULL; ++i)
    {
        check(sqlite3_bind_int(stmt_insert_argv, 2, i));
        check(sqlite3_bind_text(stmt_insert_argv, 3, argv[i],
                                -1, SQLITE_TRANSIENT));
        if(sqlite3_step(stmt_insert_argv) != SQLITE_DONE)
            goto sqlerror;
        sqlite3_reset(stmt_insert_argv);
    }

    check(sqlite3_bind_int(stmt_insert_envp, 1, rowid));
    for(i = 0; envp[i] != NULL; ++i)
    {
        char *pos = strchr(envp[i], '=');
        assert(pos != NULL);
        check(sqlite3_bind_text(stmt_insert_envp, 2, envp[i],
                                pos - envp[i], SQLITE_TRANSIENT));
        check(sqlite3_bind_text(stmt_insert_envp, 3, pos + 1,
                                -1, SQLITE_TRANSIENT));
        if(sqlite3_step(stmt_insert_envp) != SQLITE_DONE)
            goto sqlerror;
        sqlite3_reset(stmt_insert_envp);
    }

    return 0;

sqlerror:
    /* LCOV_EXCL_START : Insertions shouldn't fail */
    log_critical(0, "sqlite3 error inserting exec: %s", sqlite3_errmsg(db));
    return -1;
    /* LCOV_EXCL_END */
}

int db_add_connection(unsigned int process, int inbound, const char *family,
                      const char *protocol, const char *address)
{
    check(sqlite3_bind_int(stmt_insert_connection, 1, run_id));
    check(sqlite3_bind_int64(stmt_insert_connection, 2, gettime()));
    check(sqlite3_bind_int(stmt_insert_connection, 3, process));
    check(sqlite3_bind_int(stmt_insert_connection, 4, inbound?1:0));
    if(family == NULL)
        check(sqlite3_bind_null(stmt_insert_connection, 5));
    else
        check(sqlite3_bind_text(stmt_insert_connection, 5, family,
                                -1, SQLITE_TRANSIENT));
    if(protocol == NULL)
        check(sqlite3_bind_null(stmt_insert_connection, 6));
    else
        check(sqlite3_bind_text(stmt_insert_connection, 6, protocol,
                                -1, SQLITE_TRANSIENT));
    if(address == NULL)
        check(sqlite3_bind_null(stmt_insert_connection, 7));
    else
        check(sqlite3_bind_text(stmt_insert_connection, 7, address,
                                -1, SQLITE_TRANSIENT));

    if(sqlite3_step(stmt_insert_connection) != SQLITE_DONE)
        goto sqlerror;
    sqlite3_reset(stmt_insert_connection);
    return 0;

sqlerror:
    /* LCOV_EXCL_START : Insertions shouldn't fail */
    log_critical(0, "sqlite3 error inserting network connection: %s",
                 sqlite3_errmsg(db));
    return -1;
    /* LCOV_EXCL_END */
}
