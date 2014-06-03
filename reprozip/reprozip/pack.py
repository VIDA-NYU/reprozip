from __future__ import unicode_literals

import logging
import os
import sqlite3
import sys
import tarfile
import tempfile

from reprozip.common import FILE_WRITE, FILE_WDIR, load_config
from reprozip.utils import find_all_links


def list_directories(database):
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    executed_files = cur.execute(
            '''
            SELECT name, mode
            FROM opened_files
            WHERE mode = ? OR mode = ?
            ''',
            (FILE_WDIR, FILE_WRITE))
    # If WDIR, the name is a folder that was used as working directory
    # If WRITE, the name is a file that was written to; its directory must
    # exist
    result = set(n if m == FILE_WDIR else os.path.dirname(n)
                 for n, m in executed_files)
    cur.close()
    conn.close()
    return result


def data_path(filename, prefix='DATA/'):
    """Computes the filename to store in the archive.

    Turns an absolute path containing '..' into a filename without '..', and
    prefixes with DATA/.

    Example:

    >>> data_path('/var/lib/../../../../tmp/test')
    'DATA/tmp/test'
    >>> data_path('/var/lib/../www/index.html')
    'DATA/var/www/index.html'
    """
    return prefix + os.path.normpath(filename)[1:]


class PackBuilder(object):
    def __init__(self, filename):
        self.tar = tarfile.open(filename, 'w:gz')
        self.seen = set()

    def add(self, *args, **kwargs):
        self.tar.add(*args, **kwargs)

    def add_data(self, filename):
        if filename in self.seen:
            return
        path = '/'
        for c in filename.split(os.sep)[1:]:
            path = os.path.join(path, c)
            if path in self.seen:
                break
            logging.debug("%s -> %s" % (filename, data_path(filename)))
            self.tar.add(path, data_path(path), recursive=False)
            self.seen.add(path)

    def close(self):
        self.tar.close()
        self.seen = None


def pack(target, directory):
    """Main function for the pack subcommand.
    """
    if os.path.exists(target):
        # Don't overwrite packs...
        sys.stderr.write("Error: Target file exists!\n")
        sys.exit(1)

    # Reads configuration
    configfile = os.path.join(directory, 'config.yml')
    if not os.path.isfile(configfile):
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
    fd, manifest = tempfile.mkstemp(prefix='reprozip_', suffix='.txt')
    os.close(fd)
    try:
        with open(manifest, 'wb') as fp:
            fp.write(b'REPROZIP VERSION 1\n')
        tar.add(manifest, 'METADATA/version')
    finally:
        os.remove(manifest)

    # Stores the configuration file
    tar.add(configfile, 'METADATA/config.yml')

    # Stores the original trace
    trace = os.path.join(directory, 'trace.sqlite3')
    if os.path.isfile(trace):
        tar.add(trace, 'METADATA/trace.sqlite3')

    # Add the files from the packages
    for pkg in packages:
        if pkg.packfiles:
            logging.info("Adding files from package %s..." % pkg.name)
            for f in pkg.files:
                # This path is absolute, but not canonical
                for t in find_all_links(f.path):
                    tar.add_data(t)
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
