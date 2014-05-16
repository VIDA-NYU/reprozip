from __future__ import unicode_literals

import logging
import os
import platform
import shutil
import sqlite3

from reprozip import _pytracer
from reprozip.tracer.linux_pkgs import magic_dirs, system_dirs, \
    identify_packages
from reprozip.orderedset import OrderedSet
from reprozip.tracer.common import File, load_config, save_config


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
    READ_THEN_WRITTEN   = 0
    ONLY_READ           = 1
    WRITTEN             = 2

    what = None

    def read(self):
        if self.what is None:
            self.what = TracedFile.ONLY_READ

    def write(self):
        if self.what is None:
            self.what = TracedFile.WRITTEN
        elif self.what == TracedFile.ONLY_READ:
            self.what = TracedFile.READ_THEN_WRITTEN


def get_files(database):
    """Find all the files used by the experiment by reading the trace.
    """
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row

    files = {}

    cur = conn.cursor()
    executed_files = cur.execute('''
            SELECT name
            FROM executed_files
            ORDER BY timestamp;
            ''')
    for r_name, in executed_files:
        if r_name not in files:
            f = TracedFile(r_name)
            f.read()
            files[f.path] = f

    opened_files = cur.execute('''
            SELECT name, mode
            FROM opened_files
            ORDER BY timestamp;
            ''')
    for r_name, r_mode in opened_files:
        if r_name not in files:
            f = TracedFile(r_name)
            if r_mode & _pytracer.FILE_WRITE:
                f.write()
            elif r_mode & _pytracer.FILE_READ:
                f.read()
            else:
                continue
            files[f.path] = f
    cur.close()
    conn.close()
    return [f for f in files.values() if f.what != TracedFile.WRITTEN]


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


def trace(binary, argv, directory, append):
    """Main function for the trace subcommand.
    """
    cwd = os.getcwd()
    if (any(cwd.startswith(c) for c in magic_dirs + system_dirs) and
            not cwd.startswith('/usr/local')):
        logging.warning(
                "You are running this experiment from a system directory! "
                "Autodetection of non-system files will probably not work as "
                "intended")

    # Trace directory
    if not append:
        if os.path.exists(directory):
            logging.info("Removing existing directory %s" % directory)
            shutil.rmtree(directory)
        os.mkdir(directory)
    else:
        if not os.path.exists(directory):
            logging.warning("--continue was specified but %s does not exist "
                            "-- creating" % directory)
            os.mkdir(directory)

    # Runs the trace
    database = os.path.join(directory, 'trace.sqlite3')
    logging.info("Running program")
    c = _pytracer.execute(binary, argv, database) # Might raise _pytracer.Error
    if c != 0:
        if c & 0x0100:
            logging.warning("Program appears to have been terminated by "
                            "signal %d" % (c & 0xFF))
        else:
            logging.warning("Program exited with non-zero code %d" % c)
    logging.info("Program completed")

    # Reads info from database
    files = get_files(database)

    # Identifies which file comes from which package
    files, packages = identify_packages(files)

    # Writes configuration file
    config = os.path.join(directory, 'config.yml')
    oldconfig = os.path.exists(config)
    if oldconfig:
        # Loads in previous config
        runs, oldpkgs, oldfiles = load_config(config, File=TracedFile)
    else:
        runs, oldpkgs, oldfiles = [], [], []
    distribution = platform.linux_distribution()[0:2]
    runs.append({'binary': binary, 'argv': argv, 'workingdir': cwd,
                 'distribution': distribution})
    if oldconfig:
        files, packages = merge_files(files, packages,
                                      oldfiles,
                                      oldpkgs)

    save_config(config, runs, packages, files)

    print("Configuration file written in {}".format(config))
    print("Edit that file then run the packer -- "
          "use 'reprozip pack -h' for help")
