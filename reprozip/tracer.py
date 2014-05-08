from __future__ import unicode_literals

from datetime import datetime
import logging
import os
import platform
import shutil
import sqlite3

import reprozip
from reprozip import _pytracer
from reprozip.linux_pkgs import magic_dirs, system_dirs, Package, \
    identify_packages
from reprozip.utils import CommonEqualityMixin, Serializable, compat_execfile


class File(CommonEqualityMixin, Serializable):
    """A file, used at some point during the experiment.
    """
    def __init__(self, path):
        self.path = path
        self.what = None
        try:
            stat = os.stat(path)
        except OSError:
            self.size = None
        else:
            self.size = stat.st_size

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

    def serialize(self, fp, lvl=0, eol=False):
        fp.write(b"File('%s')" % self.string(self.path))

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.path == other.path)

    def __hash__(self):
        return hash(self.path)


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
    files = {}
    for r_name, r_mode in opened_files:
        if r_name not in files:
            f = File(r_name)
            if r_mode & _pytracer.FILE_WRITE:
                f.write()
            elif r_mode & (_pytracer.FILE_READ | _pytracer.FILE_EXEC):
                f.read()
            else:
                continue
            files[f.path] = f
    cur.close()
    conn.close()
    return [f for f in files.values() if f.what != File.WRITTEN]


def merge_files(files, packages, oldfiles, oldpackages):
    files = set(files)
    files.update(oldfiles)
    files = list(files)

    packages = dict((pkg.name, pkg) for pkg in packages)
    for oldpkg in oldpackages:
        if oldpkg.name in packages:
            pkg = packages[oldpkg.name]
            s = set(oldpkg.files)
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
        compat_execfile(config,
                        {'Package': Package, 'File': File},
                        oldconfig)
    distribution = platform.linux_distribution()[0:2]
    with open(config, 'wb') as fp:
        # Writes preamble
        runs = oldconfig.get('runs', []) + [{'binary': binary, 'argv': argv,
                                             'workingdir': cwd,
                                             'distribution': distribution}]
        if oldconfig:
            files, packages = merge_files(files, packages,
                                          oldconfig.get('other_files', []),
                                          oldconfig.get('packages', []))
        runs = "\n    " + ",\n    ".join(repr(r) for r in runs)
        fp.write(b"""\
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
            fp.write(b'    ')
            pkg.serialize(fp, 1)
            fp.write(b',\n')

        fp.write(b"""\
]

# These files do not appear to come with an installed package -- you probably
# want them packed
other_files = [
""")
        for f in files:
            fp.write(b'    ')
            f.serialize(fp, 1)
            fp.write(b', # %s\n' % f.hsize())
        fp.write(b"]\n")

    print("Configuration file written in {}".format(config))
    print("Edit that file then run the packer -- "
          "use 'reprozip pack -h' for help")
