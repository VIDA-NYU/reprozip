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
from reprozip.orderedset import OrderedSet
from reprozip.utils import CommonEqualityMixin, Serializable, \
    compat_execfile, hsize


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

    def serialize(self, fp, lvl=0, eol=False):
        fp.write("File(%s)" % self.string(self.path))

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

    files = {}

    cur = conn.cursor()
    executed_files = cur.execute('''
            SELECT name
            FROM executed_files
            ORDER BY timestamp;
            ''')
    for r_name, in executed_files:
        if r_name not in files:
            f = File(r_name)
            f.read()
            files[f.path] = f

    opened_files = cur.execute('''
            SELECT name, mode
            FROM opened_files
            ORDER BY timestamp;
            ''')
    for r_name, r_mode in opened_files:
        if r_name not in files:
            f = File(r_name)
            if r_mode & _pytracer.FILE_WRITE:
                f.write()
            elif r_mode & _pytracer.FILE_READ:
                f.read()
            else:
                continue
            files[f.path] = f
    cur.close()
    conn.close()
    return [f for f in files.values() if f.what != File.WRITTEN]


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
    config = os.path.join(directory, 'config.py')
    oldconfig = {}
    if os.path.exists(config):
        # Loads in previous config
        compat_execfile(config,
                        {'Package': Package, 'File': File},
                        oldconfig)
    distribution = platform.linux_distribution()[0:2]
    with open(config, 'w') as fp:
        # Writes preamble
        runs = oldconfig.get('runs', []) + [{'binary': binary, 'argv': argv,
                                             'workingdir': cwd,
                                             'distribution': distribution}]
        if oldconfig:
            files, packages = merge_files(files, packages,
                                          oldconfig.get('other_files', []),
                                          oldconfig.get('packages', []))
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
            fp.write('    ')
            pkg.serialize(fp, 1)
            fp.write(',\n')

        fp.write("""\
]

# These files do not appear to come with an installed package -- you probably
# want them packed
other_files = [
""")
        for f in files:
            fp.write('    ')
            f.serialize(fp, 1)
            fp.write(', # %s\n' % hsize(f.size))
        fp.write("]\n")

    print("Configuration file written in {}".format(config))
    print("Edit that file then run the packer -- "
          "use 'reprozip pack -h' for help")
