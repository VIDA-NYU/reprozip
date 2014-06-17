from __future__ import unicode_literals

import logging
import os
from rpaths import Path
import sqlite3
import sys
import tarfile

from reprozip.common import FILE_WRITE, FILE_WDIR, load_config
from reprozip.utils import PY3


def list_directories(database):
    if PY3:
        # On Python 3, connect() only accepts unicode
        conn = sqlite3.connect(str(database))
    else:
        conn = sqlite3.connect(database.path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    executed_files = cur.execute(
            '''
            SELECT name, mode
            FROM opened_files
            WHERE mode = ? OR mode = ?
            ''',
            (FILE_WDIR, FILE_WRITE))
    executed_files = ((Path(n), m) for n, m in executed_files)
    # If WDIR, the name is a folder that was used as working directory
    # If WRITE, the name is a file that was written to; its directory must
    # exist
    result = set(n if m == FILE_WDIR else n.parent
                 for n, m in executed_files)
    cur.close()
    conn.close()
    return result


def data_path(filename, prefix=Path('DATA')):
    """Computes the filename to store in the archive.

    Turns an absolute path containing '..' into a filename without '..', and
    prefixes with DATA/.

    Example:

    >>> data_path(PosixPath('/var/lib/../../../../tmp/test'))
    PosixPath(b'DATA/tmp/test')
    >>> data_path(PosixPath('/var/lib/../www/index.html'))
    PosixPath(b'DATA/var/www/index.html')
    """
    return prefix / filename.split_root()[1]


class PackBuilder(object):
    def __init__(self, filename):
        self.tar = tarfile.open(str(filename), 'w:gz')
        self.seen = set()

    def add(self, name, arcname, *args, **kwargs):
        from rpaths import PosixPath
        assert isinstance(name, PosixPath)
        assert isinstance(arcname, PosixPath)
        self.tar.add(str(name), str(arcname), *args, **kwargs)

    def add_data(self, filename):
        if filename in self.seen:
            return
        path = Path('/')
        for c in filename.components[1:]:
            path = path / c
            if path in self.seen:
                continue
            logging.debug("%s -> %s" % (path, data_path(path)))
            self.tar.add(str(path), str(data_path(path)), recursive=False)
            self.seen.add(path)

    def close(self):
        self.tar.close()
        self.seen = None


def pack(target, directory):
    """Main function for the pack subcommand.
    """
    if target.exists():
        # Don't overwrite packs...
        sys.stderr.write("Error: Target file exists!\n")
        sys.exit(1)

    # Reads configuration
    configfile = directory / 'config.yml'
    if not configfile.is_file():
        sys.stderr.write("Error: Configuration file does not exist!\n"
                         "Did you forget to run 'reprozip trace'?\n"
                         "If not, you might want to use --dir to specify an "
                         "alternate location.\n")
        sys.exit(1)
    runs, packages, other_files = load_config(configfile)

    logging.info("Creating pack %s..." % target)
    tar = PackBuilder(target)

    logging.info("Adding metadata...")
    # Stores pack version
    fd, manifest = Path.tempfile(prefix='reprozip_', suffix='.txt')
    os.close(fd)
    try:
        with manifest.open('wb') as fp:
            fp.write(b'REPROZIP VERSION 1\n')
        tar.add(manifest, Path('METADATA/version'))
    finally:
        manifest.remove()

    # Stores the configuration file
    tar.add(configfile, Path('METADATA/config.yml'))

    # Stores the original trace
    trace = directory / 'trace.sqlite3'
    if trace.is_file():
        tar.add(trace, Path('METADATA/trace.sqlite3'))

    # Add the files from the packages
    for pkg in packages:
        if pkg.packfiles:
            logging.info("Adding files from package %s..." % pkg.name)
            for f in pkg.files:
                tar.add_data(f.path)
        else:
            logging.info("NOT adding files from package %s" % pkg.name)

    # Add the rest of the files
    logging.info("Adding other files...")
    for f in other_files:
        tar.add_data(f.path)

    # Makes sure all the directories used as working directories are packed
    # (they already do if files from them are used, but empty directories do
    # not get packed inside a tar archive)
    for directory in list_directories(trace):
        tar.add_data(directory)

    tar.close()
