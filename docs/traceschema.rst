..  _trace-schema:

Trace Database Schema
*********************

The database contains three tables: ``processes``, ``opened_files``, and ``executed_files``.

``processes``
'''''''''''''

This table contains information about all the processes. A process is identified by Linux as a *pid* (process id), and is either a thread or a full-fledged process.

Note that processes are different from programs, and there is no one-to-one relationship with executions. A process is created by `clone(2) <https://linux.die.net/man/2/clone>`__ or `fork(2) <https://linux.die.net/man/2/fork>`__ and not necessarily followed by `execve(2) <https://linux.die.net/man/2/execve>`__. By contrast, a program can change its image by calling execve(2) without creating new processes (i.e., without changing *pid*).

Each entry in the ``processes`` table has the id of its parent, i.e. the process that created it by calling clone(2) or fork(2), except the original process that *reprozip* created, for which parent is NULL. There is thus exactly one process with a NULL parent per run stored in the pack.

::

    CREATE TABLE processes(
        id INTEGER NOT NULL PRIMARY KEY,
        run_id INTEGER NOT NULL,
        parent INTEGER,
        timestamp INTEGER NOT NULL,
        is_thread BOOLEAN NOT NULL,
        exitcode INTEGER
        );

``opened_files``
''''''''''''''''

This table contains information regarding the files accessed by the processes. Note that a failed access (e.g.: trying to read a non-existing file, permission denied, etc.) is not logged. A single path might appear several times, even if accessed by the same process.

Each file has a numerical id, the canonical path name, the process that accessed it (from which you can get the executable by cross-referencing ``processes``, also using the timestamp), and the mode.

::

    CREATE TABLE opened_files(
        id INTEGER NOT NULL PRIMARY KEY,
        run_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        mode INTEGER NOT NULL,
        is_directory BOOLEAN NOT NULL,
        process INTEGER NOT NULL
        );

The *mode* attribute is a binary OR of the following values (accessible from ``reprounzip.common``)::

    FILE_READ   = 0x01
    FILE_WRITE  = 0x02
    FILE_WDIR   = 0x04
    FILE_STAT   = 0x08
    FILE_LINK   = 0x10

``executed_files``
''''''''''''''''''

This is a variant of ``opened_files`` for file executions, i.e. `execve(2) <https://linux.die.net/man/2/execve>`__ calls. There is no mode here (file is opened for reading by the call) and they are never directories; however, *workingdir*, *argv* (command-line arguments) and *envp* (environment variables) are added. *argv* is a list of arguments separated by null bytes (``0x00``) [#nullbytes]_, and *envp* is a list of ``VAR=value`` pairs separated by null (``0x00``) bytes [#nullbytes]_. Note that, again, failed executions (execve returns) are not logged.

::

    CREATE TABLE executed_files(
        id INTEGER NOT NULL PRIMARY KEY,
        name TEXT NOT NULL,
        run_id INTEGER NOT NULL,
        timestamp INTEGER NOT NULL,
        process INTEGER NOT NULL,
        argv TEXT NOT NULL,
        envp TEXT NOT NULL,
        workingdir TEXT NOT NULL
        );

..  [#nullbytes] Note that Python's sqlite3 lib is affected by `bug 13676 <https://bugs.python.org/issue13676>`__ up to Python 2.7.3, which prevents it from reading text or blob fields with embedded null bytes.
