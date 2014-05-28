from __future__ import unicode_literals

import logging
import os
import sys
import tarfile
import tempfile

from reprozip.common import load_config
from reprozip.utils import find_all_links


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
    tar = tarfile.open(target, 'w:gz')

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
                    logging.debug("%s -> %s" % (t, data_path(t)))
                    tar.add(t, data_path(t))
        else:
            logging.info("NOT adding files from package %s" % pkg.name)

    # Add the rest of the files
    logging.info("Adding other files...")
    for f in other_files:
        logging.debug("%s -> %s" % (os.path.abspath(f.path),
                                    data_path(f.path)))
        tar.add(f.path, data_path(f.path))

    tar.close()
