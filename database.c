#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sqlite3.h>

#define count(x) (sizeof((x))/sizeof(*(x)))
#define check(r) if((r) != SQLITE_OK) { goto sqlerror; }

static sqlite3 *db;
static sqlite3_stmt *stmt_last_rowid;
static sqlite3_stmt *stmt_insert_process;
static sqlite3_stmt *stmt_insert_file;

int db_init(const char *filename)
{
    int tables_exist;

    check(sqlite3_open(filename, &db));

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
            if(strcmp("processes", colname) == 0)
                found |= 0x01;
            else if(strcmp("opened_files", colname) == 0)
                found |= 0x02;
            else
                goto wrongschema;
        }
        if(found == 0x00)
            tables_exist = 0;
        else if(found == 0x03)
            tables_exist = 1;
        else
        {
        wrongschema:
            fprintf(stderr, "Database schema is wrong\n");
            return -1;
        }
        sqlite3_finalize(stmt_get_tables);
        if(ret != SQLITE_DONE)
            goto sqlerror;
    }

    if(!tables_exist)
    {
        const char *sql[] = {
            "CREATE TABLE processes("
            "    id INTEGER NOT NULL PRIMARY KEY,"
            "    parent INTEGER,"
            "    timestamp INTEGER NOT NULL"
            "    );",

            "CREATE TABLE opened_files("
            "    id INTEGER NOT NULL PRIMARY KEY,"
            "    name TEXT NOT NULL,"
            "    timestamp INTEGER NOT NULL,"
            "    mode INTEGER NOT NULL,"
            "    process INTEGER NOT NULL"
            "    );",
        };
        size_t i;
        for(i = 0; i < count(sql); ++i)
            check(sqlite3_exec(db, sql[i], NULL, NULL, NULL));
    }

    {
        const char *sql = ""
                "SELECT last_insert_rowid()";
        check(sqlite3_prepare_v2(db, sql, -1, &stmt_last_rowid, NULL));
    }

    {
        const char *sql = ""
                "INSERT INTO processes(parent, timestamp)"
                "VALUES(?, ?)";
        check(sqlite3_prepare_v2(db, sql, -1, &stmt_insert_process, NULL));
    }

    {
        const char *sql = ""
                "INSERT INTO opened_files(name, timestamp, mode, process)"
                "VALUES(?, ?, ?, ?)";
        check(sqlite3_prepare_v2(db, sql, -1, &stmt_insert_file, NULL));
    }

    return 0;

sqlerror:
    fprintf(stderr, "sqlite3 error creating database: %s\n",
            sqlite3_errmsg(db));
    return -1;
}

int db_close(void)
{
    check(sqlite3_finalize(stmt_last_rowid));
    check(sqlite3_finalize(stmt_insert_process));
    check(sqlite3_finalize(stmt_insert_file));
    check(sqlite3_close(db));
    return 0;

sqlerror:
    fprintf(stderr, "sqlite3 error on exit: %s\n", sqlite3_errmsg(db));
    return -1;
}

#define DB_NO_PARENT ((unsigned int)-2)

int db_add_process(unsigned int *id, unsigned int parent_id)
{
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC, &now) == -1)
    {
        perror("Getting time failed (clock_gettime)");
        return -1;
    }
    if(parent_id == DB_NO_PARENT)
    {
        check(sqlite3_bind_null(stmt_insert_process, 1));
    }
    else
    {
        check(sqlite3_bind_int(stmt_insert_process, 1, parent_id));
    }
    {
        /* This assumes that we won't go over 2^32 seconds (~135 years) */
        sqlite3_uint64 timestamp;
        timestamp = now.tv_sec;
        timestamp *= 1000000000;
        timestamp += now.tv_nsec;
        check(sqlite3_bind_int64(stmt_insert_process, 2, timestamp));
    }

    if(sqlite3_step(stmt_insert_process) != SQLITE_DONE)
        goto sqlerror;
    sqlite3_reset(stmt_insert_process);

    /* Get id */
    if(sqlite3_step(stmt_last_rowid) != SQLITE_ROW)
        goto sqlerror;
    *id = sqlite3_column_int(stmt_last_rowid, 0);
    if(sqlite3_step(stmt_last_rowid) != SQLITE_DONE)
        goto sqlerror;
    sqlite3_reset(stmt_last_rowid);

    return 0;

sqlerror:
    fprintf(stderr, "sqlite3 error inserting process: %s\n",
            sqlite3_errmsg(db));
    return -1;
}

int db_add_first_process(unsigned int *id)
{
    return db_add_process(id, DB_NO_PARENT);
}

int db_add_file_open(unsigned int process, const char *name, unsigned int mode)
{
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC, &now) == -1)
    {
        perror("Getting time failed (clock_gettime)");
        return -1;
    }
    check(sqlite3_bind_text(stmt_insert_file, 1, name, -1, SQLITE_TRANSIENT));
    {
        /* This assumes that we won't go over 2^32 seconds (~135 years) */
        sqlite3_uint64 timestamp;
        timestamp = now.tv_sec;
        timestamp *= 1000000000;
        timestamp += now.tv_nsec;
        check(sqlite3_bind_int64(stmt_insert_file, 2, timestamp));
    }
    check(sqlite3_bind_int(stmt_insert_file, 3, mode));
    check(sqlite3_bind_int(stmt_insert_file, 4, process));

    if(sqlite3_step(stmt_insert_file) != SQLITE_DONE)
        goto sqlerror;
    sqlite3_reset(stmt_insert_file);
    return 0;

sqlerror:
    fprintf(stderr, "sqlite3 error inserting file: %s\n",
            sqlite3_errmsg(db));
    return -1;
}
