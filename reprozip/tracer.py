from __future__ import unicode_literals

from datetime import datetime
import logging
import os
import platform
import shutil
import sqlite3

import reprozip
from reprozip import _pytracer
from reprozip.linux_pkgs import identify_packages, magic_dirs, system_dirs


def escape(s):
    return "'%s'" % s.replace('\\', '\\\\').replace("'", "\\'")


class File(object):
    """A file, used at some point during the experiment.
    """
    def __init__(self, path):
        self.path = path
        self.what = None
        stat = os.stat(path)
        if stat is not None:
            self.size = stat.st_size
        else:
            self.size = None

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

    def read(self):
        if self.what is None:
            self.what = File.ONLY_READ

    def write(self):
        if self.what is None:
            self.what = File.WRITTEN
        elif self.what == File.ONLY_READ:
            self.what = File.READ_THEN_WRITTEN

    def hsize(self):
        """Readable size.
        """
        if self.size is None:
            return "unknown"

        KB = 1<<10
        MB = 1<<20
        GB = 1<<30
        TB = 1<<40
        PB = 1<<50

        bytes = float(self.size)

        if bytes < KB:
            return "{} bytes".format(self.size)
        elif bytes < MB:
            return "{:.2f} KB".format(bytes / KB)
        elif bytes < GB:
            return "{:.2f} MB".format(bytes / MB)
        elif bytes < TB:
            return "{:.2f} GB".format(bytes / GB)
        elif bytes < PB:
            return "{:.2f} TB".format(bytes / TB)
        else:
            return "{:.2f} PB".format(bytes / PB)

    def __str__(self):
        return "File(%s, %d)" % (self.path, self.what)
    __repr__ = __str__


def get_files(database):
    """Find all the files used by the experiment by reading the trace.
    """
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row

    cur = conn.cursor()
    opened_files = cur.execute('''
            SELECT name, mode
            FROM opened_files
            ORDER BY timestamp;
            ''')
    files = []
    for r_name, r_mode in opened_files:
        if r_name not in files:
            f = File(r_name)
            if r_mode & _pytracer.FILE_WRITE:
                f.write()
            elif r_mode & (_pytracer.FILE_READ | _pytracer.FILE_EXEC):
                f.read()
            else:
                continue
            files.append(f)
    cur.close()
    conn.close()
    return [f for f in files if f.what != File.WRITTEN]


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
    _pytracer.execute(binary, argv, database) # Might raise _pytracer.Error
    logging.info("Program completed")

    # Reads info from database
    files = get_files(database)

    # Identifies which file comes from which package
    files, packages = identify_packages(files)

    # Writes configuration file
    config = os.path.join(directory, 'config.py')
    oldconfig = {}
    if os.path.exists(config):
        # Loads in previous config
        execfile(config, oldconfig)
    distribution = platform.linux_distribution()[0:2]
    with open(config, 'w') as fp:
        # Writes preamble
        runs = oldconfig.get('runs', []) + [{'binary': binary, 'argv': argv,
                                             'workingdir': cwd,
                                             'distribution': distribution}]
        runs = "\n    " + ",\n    ".join(repr(r) for r in runs)
        fp.write("""\
# ReproZip configuration file
# This file was generated by reprozip {version} at {date}

# You might want to edit this file before running the packer
# See 'reprozip pack -h' for help

# Run info
version = '{version}'
runs = [{runs}
]


# Files to pack
# All the files below were used by the program; they will be included in the
# generated package

# These files come from packages; we can thus choose not to include them, as it
# will simply be possible to install that package on the destination system
# They are included anyway by default
packages = [
""".format(
            version=reprozip.__version__,
            date=datetime.now().isoformat(),
            runs=runs))

        # Writes files
        for pkg in packages:
            fp.write("    Package(name={n}{v}, packfiles=True, "
                     "files=[\n".format(
                     n=escape(pkg.name),
                     v=(", version={}".format(escape(pkg.version))
                        if pkg.version is not None
                        else "")))
            for f in pkg.files:
                fp.write("        File(%s), # %s\n" % (escape(f.path),
                                                       f.hsize()))
            fp.write("    ]),\n")

        fp.write("""\
]

# These files do not appear to come with an installed package -- you probably
# want them packed
other_files = [
""")
        for f in files:
            fp.write("    File(%s), # %s\n" % (escape(f.path),
                                               f.hsize()))
        fp.write("]\n")

    print("Configuration file written in {}".format(config))
    print("Edit that file then run the packer -- "
          "use 'reprozip pack -h' for help")
