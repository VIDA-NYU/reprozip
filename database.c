#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define count(x) (sizeof((x))/sizeof(*(x)))
#define check(r) if((r) != SQLITE_OK) { goto sqlerror; }

static sqlite3 *db;
static sqlite3_stmt *stmt_insert_process;
static sqlite3_stmt *stmt_insert_file;

int db_init(const char *filename)
{
    check(sqlite3_open(filename, &db));

    {
        const char *sql[] = {
            "CREATE TABLE processes("
            "    id INTEGER NOT NULL PRIMARY KEY,"
            "    parent INTEGER,"
            "    binary TEXT NOT NULL,"
            "    commandline TEXT NOT NULL"
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
                "INSERT INTO processes(id, parent, binary, commandline)"
                "VALUES(?, ?, ?, ?)";
        check(sqlite3_prepare_v2(db, sql, -1, &stmt_insert_process, NULL));
    }

    {
        const char *sql = ""
                "INSERT INTO opened_files(name, timestamp, mode, process)"
                "VALUES(?, datetime(), ?, ?)";
        check(sqlite3_prepare_v2(db, sql, -1, &stmt_insert_file, NULL));
    }

    return 0;

sqlerror:
    fprintf(stderr, "sqlite3 error creating database: %s\n",
            sqlite3_errmsg(db));
    return 1;
}

int db_close()
{
    check(sqlite3_finalize(stmt_insert_process));
    check(sqlite3_finalize(stmt_insert_file));
    check(sqlite3_close(db));
    return 0;

sqlerror:
    fprintf(stderr, "sqlite3 error on exit: %s\n", sqlite3_errmsg(db));
    return 1;
}

#define DB_NO_PARENT ((unsigned int)-2)

int db_add_process(unsigned int id, unsigned int parent_id,
                   const char *binary,
                   size_t argc, const char **argv)
{
    check(sqlite3_bind_int(stmt_insert_process, 1, id));
    if(parent_id == DB_NO_PARENT)
    {
        check(sqlite3_bind_null(stmt_insert_process, 2));
    }
    else
    {
        check(sqlite3_bind_int(stmt_insert_process, 2, parent_id));
    }
    check(sqlite3_bind_text(stmt_insert_process, 3, binary, -1,
                            SQLITE_TRANSIENT));
    {
        size_t commandline_size = 0;
        size_t i, j = 0;
        char *commandline;
        for(i = 0; i < argc; ++i)
            commandline_size += strlen(argv[i]) + 1;
        commandline = malloc(commandline_size);
        for(i = 0; i < argc; ++i)
        {
            const char *arg = argv[i];
            while(*arg)
                commandline[j++] = *arg++;
            commandline[j++] = '\t';
        }
        commandline[(j>0)?j-1:0] = '\0';
        check(sqlite3_bind_text(stmt_insert_process, 4, commandline, -1, free));
    }

    if(sqlite3_step(stmt_insert_process) != SQLITE_DONE)
        goto sqlerror;
    sqlite3_reset(stmt_insert_process);

    return 0;

sqlerror:
    fprintf(stderr, "sqlite3 error inserting process: %s\n",
            sqlite3_errmsg(db));
    return 1;
}

int db_add_first_process(unsigned int id, const char *binary,
                         size_t argc, const char **argv)
{
    return db_add_process(id, DB_NO_PARENT, binary, argc, argv);
}

int db_add_file_open(unsigned int process, const char *name, unsigned int mode)
{
    check(sqlite3_bind_text(stmt_insert_file, 1, name, -1, SQLITE_TRANSIENT));
    check(sqlite3_bind_int(stmt_insert_file, 2, mode));
    check(sqlite3_bind_int(stmt_insert_file, 3, process));

    if(sqlite3_step(stmt_insert_file) != SQLITE_DONE)
        goto sqlerror;
    sqlite3_reset(stmt_insert_file);
    return 0;

sqlerror:
    fprintf(stderr, "sqlite3 error inserting file: %s\n",
            sqlite3_errmsg(db));
    return 1;
}
