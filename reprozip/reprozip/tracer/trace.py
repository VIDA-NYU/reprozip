# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import unicode_literals

import heapq
import logging
import os
import platform
from rpaths import Path
import sqlite3

from reprozip import __version__ as reprozip_version
from reprozip import _pytracer
from reprozip.common import File, load_config, save_config, \
    FILE_READ, FILE_WRITE
from reprozip.orderedset import OrderedSet
from reprozip.tracer.linux_pkgs import magic_dirs, system_dirs, \
    identify_packages
from reprozip.utils import PY3, hsize, find_all_links


class TracedFile(File):
    #                               read
    #                              +------+
    #                              |      |
    #                read          v      +   write
    # (init) +------------------> ONLY_READ +-------> READ_THEN_WRITTEN
    #        |                                           ^         +
    #        |                                           |         |
    #        +-------> WRITTEN +--+                      +---------+
    #          write    ^         |                      read, write
    #                   |         |
    #                   +---------+
    #                   read, write
    READ_THEN_WRITTEN = 0
    ONLY_READ = 1
    WRITTEN = 2

    what = None

    def __init__(self, path):
        path = Path(path)
        size = None
        if path.exists():
            if path.is_link():
                self.comment = "Link to %s" % path.read_link(absolute=True)
            elif path.is_dir():
                self.comment = "Directory"
            else:
                size = path.size()
                self.comment = hsize(size)
        File.__init__(self, path, size)

    def read(self):
        if self.what is None:
            self.what = TracedFile.ONLY_READ

    def write(self):
        if self.what is None:
            self.what = TracedFile.WRITTEN
        elif self.what == TracedFile.ONLY_READ:
            self.what = TracedFile.READ_THEN_WRITTEN


def get_files(conn):
    """Find all the files used by the experiment by reading the trace.
    """
    files = {}

    # Adds dynamic linkers
    for libdir in (Path('/lib'), Path('/lib64')):
        if libdir.exists():
            for linker in libdir.listdir('*ld-linux*'):
                f = TracedFile(linker)
                f.read()
                files[f.path] = f

    # Adds executed files
    exec_cursor = conn.cursor()
    executed_files = exec_cursor.execute(
            '''
            SELECT name, timestamp
            FROM executed_files
            ORDER BY timestamp;
            ''')
    # ... and opened files
    open_cursor = conn.cursor()
    opened_files = open_cursor.execute(
            '''
            SELECT name, mode, timestamp
            FROM opened_files
            ORDER BY timestamp;
            ''')
    # Loop on both lists at once
    rows = heapq.merge(((r[1], 'exec', r) for r in executed_files),
                       ((r[2], 'open', r) for r in opened_files))
    for ts, event_type, data in rows:
        if event_type == 'exec':
            r_name, r_timestamp = data
            for filename in find_all_links(r_name, True):
                if filename not in files:
                    f = TracedFile(filename)
                    f.read()
                    files[f.path] = f

        elif event_type == 'open':
            r_name, r_mode, r_timestamp = data
            r_name = Path(r_name)
            # Adds symbolic links as read files
            for filename in find_all_links(r_name, False):
                if filename not in files:
                    f = TracedFile(filename)
                    f.read()
                    files[f.path] = f
            # Adds final target
            r_name = r_name.resolve()
            if r_name not in files:
                f = TracedFile(r_name)
                files[f.path] = f
            else:
                f = files[f.path]
            if r_mode & FILE_WRITE:
                f.write()
            elif r_mode & FILE_READ:
                f.read()
    exec_cursor.close()
    open_cursor.close()

    return [fi
            for fi in files.values()
            if fi.what != TracedFile.WRITTEN and not any(fi.path.lies_under(m)
                                                         for m in magic_dirs)]


def merge_files(newfiles, newpackages, oldfiles, oldpackages):
    files = OrderedSet(oldfiles)
    files.update(newfiles)
    files = list(files)

    packages = dict((pkg.name, pkg) for pkg in newpackages)
    for oldpkg in oldpackages:
        if oldpkg.name in packages:
            pkg = packages[oldpkg.name]
            s = OrderedSet(oldpkg.files)
            s.update(pkg.files)
            oldpkg.files = list(s)
            packages[oldpkg.name] = oldpkg
        else:
            packages[oldpkg.name] = oldpkg
    packages = list(packages.values())

    return files, packages


def trace(binary, argv, directory, append, verbosity=1):
    """Main function for the trace subcommand.
    """
    cwd = Path.cwd()
    if (any(cwd.lies_under(c) for c in magic_dirs + system_dirs) and
            not cwd.lies_under('/usr/local')):
        logging.warning(
                "You are running this experiment from a system directory! "
                "Autodetection of non-system files will probably not work as "
                "intended")

    # Trace directory
    if not append:
        if directory.exists():
            logging.info("Removing existing directory %s" % directory)
            directory.rmtree()
        directory.mkdir(parents=True)
    else:
        if not directory.exists():
            logging.warning("--continue was specified but %s does not exist "
                            "-- creating" % directory)
            directory.mkdir(parents=True)

    # Runs the trace
    database = directory / 'trace.sqlite3'
    logging.info("Running program")
    # Might raise _pytracer.Error
    c = _pytracer.execute(binary, argv, database.path, verbosity)
    if c != 0:
        if c & 0x0100:
            logging.warning("Program appears to have been terminated by "
                            "signal %d" % (c & 0xFF))
        else:
            logging.warning("Program exited with non-zero code %d" % c)
    logging.info("Program completed")


def write_configuration(directory, sort_packages, overwrite=False):
    database = directory / 'trace.sqlite3'

    if PY3:
        # On PY3, connect() only accepts unicode
        conn = sqlite3.connect(str(database))
    else:
        conn = sqlite3.connect(database.path)
    conn.row_factory = sqlite3.Row

    # Reads info from database
    files = get_files(conn)

    # Identifies which file comes from which package
    if sort_packages:
        files, packages = identify_packages(files)
    else:
        packages = []

    # Writes configuration file
    config = directory / 'config.yml'
    distribution = platform.linux_distribution()[0:2]
    oldconfig = not overwrite and config.exists()
    cur = conn.cursor()
    if oldconfig:
        # Loads in previous config
        runs, oldpkgs, oldfiles, patterns = load_config(config,
                                                        canonical=False,
                                                        File=TracedFile)

        executions = cur.execute(
                '''
                SELECT e.name, e.argv, e.envp, e.workingdir, p.exitcode
                FROM executed_files e
                INNER JOIN processes p on p.id=e.id
                WHERE p.parent ISNULL
                ORDER BY p.id DESC
                LIMIT 1;
                ''')

        files, packages = merge_files(files, packages,
                                      oldfiles,
                                      oldpkgs)
    else:
        runs = []
        executions = cur.execute(
                '''
                SELECT e.name, e.argv, e.envp, e.workingdir, p.exitcode
                FROM executed_files e
                INNER JOIN processes p on p.id=e.id
                WHERE p.parent ISNULL
                ORDER BY p.id;
                ''')
    for r_name, r_argv, r_envp, r_workingdir, r_exitcode in executions:
        argv = r_argv.split('\0')
        if not argv[-1]:
            argv = argv[:-1]
        envp = r_envp.split('\0')
        if not envp[-1]:
            envp = envp[:-1]
        environ = dict(v.split('=', 1) for v in envp)
        runs.append({'binary': r_name, 'argv': argv,
                     'workingdir': Path(r_workingdir).path,
                     'architecture': platform.machine(),
                     'distribution': distribution,
                     'hostname': platform.node(),
                     'system': [platform.system(), platform.release()],
                     'environ': environ,
                     'uid': os.getuid(),
                     'gid': os.getgid(),
                     'signal' if r_exitcode & 0x0100 else 'exitcode':
                         r_exitcode & 0xFF})
    cur.close()

    conn.close()

    save_config(config, runs, packages, files, reprozip_version)

    print("Configuration file written in {0!s}".format(config))
    print("Edit that file then run the packer -- "
          "use 'reprozip pack -h' for help")
