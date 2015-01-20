# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

# This file is shared:
#   reprozip/reprozip/utils.py
#   reprounzip/reprounzip/utils.py

"""Utility functions.

These functions are shared between reprozip and reprounzip but are not specific
to this software (more utilities).

"""

from __future__ import unicode_literals

import contextlib
import email.utils
import logging
import os
from rpaths import Path
import stat
import subprocess
import sys


PY3 = sys.version_info[0] == 3


if PY3:
    from urllib.error import HTTPError, URLError
    from urllib.request import Request, urlopen
    izip = zip
    irange = range
    iteritems = dict.items
    itervalues = dict.values
    listvalues = lambda d: list(d.values())
else:
    from urllib2 import Request, HTTPError, URLError, urlopen
    import itertools
    izip = itertools.izip
    irange = xrange
    iteritems = dict.iteritems
    itervalues = dict.itervalues
    listvalues = dict.values


if PY3:
    unicode_ = str
else:
    unicode_ = unicode


def escape(s):
    """Escapes backslashes and double quotes in strings.

    This does NOT add quotes around the string.
    """
    return s.replace('\\', '\\\\').replace('"', '\\"')


class CommonEqualityMixin(object):
    """Common mixin providing comparison by comparing ``__dict__`` attributes.
    """
    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)

    def __ne__(self, other):
        return not self.__eq__(other)


def hsize(nbytes):
    """Readable size.
    """
    if nbytes is None:
        return "unknown"

    KB = 1 << 10
    MB = 1 << 20
    GB = 1 << 30
    TB = 1 << 40
    PB = 1 << 50

    nbytes = float(nbytes)

    if nbytes < KB:
        return "{0} bytes".format(nbytes)
    elif nbytes < MB:
        return "{0:.2f} KB".format(nbytes / KB)
    elif nbytes < GB:
        return "{0:.2f} MB".format(nbytes / MB)
    elif nbytes < TB:
        return "{0:.2f} GB".format(nbytes / GB)
    elif nbytes < PB:
        return "{0:.2f} TB".format(nbytes / TB)
    else:
        return "{0:.2f} PB".format(nbytes / PB)


def find_all_links_recursive(filename, files):
    path = Path('/')
    for c in filename.components[1:]:
        # At this point, path is a canonical path, and all links in it have
        # been resolved

        # We add the next path component
        path = path / c

        # That component is possibly a link
        if path.is_link():
            # Adds the link itself
            files.add(path)

            target = path.read_link(absolute=True)
            # Here, target might contain a number of symlinks
            if target not in files:
                # Recurse on this new path
                find_all_links_recursive(target, files)
            # Restores the invariant; realpath might resolve several links here
            path = path.resolve()
    return path


def find_all_links(filename, include_target=False):
    """Dereferences symlinks from a path.

    If include_target is True, this also returns the real path of the final
    target.

    Example:
        /
            a -> b
            b
                g -> c
                c -> ../a/d
                d
                    e -> /f
            f
    >>> find_all_links('/a/g/e', True)
    ['/a', '/b/c', '/b/g', '/b/d/e', '/f']
    """
    files = set()
    filename = Path(filename)
    assert filename.absolute()
    path = find_all_links_recursive(filename, files)
    files = list(files)
    if include_target:
        files.append(path)
    return files


@contextlib.contextmanager
def make_dir_writable(directory):
    """Context-manager that sets write permission on a directory.

    This assumes that the directory belongs to you. If the u+w permission
    wasn't set, it gets set in the context, and restored to what it was when
    leaving the context. u+x also gets set on all the directories leading to
    that path.
    """
    uid = os.getuid()

    try:
        sb = directory.stat()
    except OSError:
        pass
    else:
        if sb.st_uid != uid or sb.st_mode & 0o700 == 0o700:
            yield
            return

    # These are the permissions to be restored, in reverse order
    restore_perms = []
    try:
        # Add u+x to all directories up to the target
        path = Path('/')
        for c in directory.components[1:-1]:
            path = path / c
            sb = path.stat()
            if sb.st_uid == uid and not sb.st_mode & 0o100:
                logging.debug("Temporarily setting u+x on %s", path)
                restore_perms.append((path, sb.st_mode))
                path.chmod(sb.st_mode | 0o700)

        # Add u+wx to the target
        sb = directory.stat()
        if sb.st_uid == uid and sb.st_mode & 0o700 != 0o700:
            logging.debug("Temporarily setting u+wx on %s", directory)
            restore_perms.append((directory, sb.st_mode))
            directory.chmod(sb.st_mode | 0o700)

        yield
    finally:
        for path, mod in reversed(restore_perms):
            path.chmod(mod)


def rmtree_fixed(path):
    """Like :func:`shutil.rmtree` but doesn't choke on annoying permissions.

    If a directory with -w or -x is encountered, it gets fixed and deletion
    continues.
    """
    if path.is_link():
        raise OSError("Cannot call rmtree on a symbolic link")

    uid = os.getuid()
    st = path.lstat()

    if st.st_uid == uid and st.st_mode & 0o700 != 0o700:
        path.chmod(st.st_mode | 0o700)

    for entry in path.listdir():
        if stat.S_ISDIR(entry.lstat().st_mode):
            rmtree_fixed(entry)
        else:
            entry.remove()

    path.rmdir()


def check_output(*popenargs, **kwargs):
    """Runs a command and returns its output, raising on non-zero exit code.
    """
    if 'stdout' in kwargs:
        raise ValueError("stdout argument not allowed")
    process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
    stdout, stderr = process.communicate()
    retcode = process.poll()
    if retcode:
        cmd = kwargs.get('args')
        if cmd is None:
            cmd = [popenargs[0]]
        raise subprocess.CalledProcessError(retcode, cmd)
    return stdout


def download_file(url, dest, cachename=None):
    """Downloads a file using a local cache.

    If the file cannot be downloaded or if it wasn't modified, the cached
    version will be used instead.

    The cache lives in ``~/.cache/reprozip/``.
    """
    if cachename is None:
        cachename = dest.name

    request = Request(url)

    if 'XDG_CACHE_HOME' in os.environ:
        cache = Path(os.environ['XDG_CACHE_HOME'])
    else:
        cache = Path('~/.cache').expand_user()
    cache = cache / 'reprozip' / cachename
    if cache.exists():
        mtime = email.utils.formatdate(cache.mtime(), usegmt=True)
        request.add_header('If-Modified-Since', mtime)

    cache.parent.mkdir(parents=True)

    try:
        response = urlopen(request)
    except URLError as e:
        if cache.exists():
            if isinstance(e, HTTPError) and e.code == 304:
                logging.info("Cached file %s is up to date", cachename)
            else:
                logging.warning("Couldn't download %s: %s", url, e)
            cache.copy(dest)
            return
        else:
            raise

    if response is None:
        logging.info("Cached file %s is up to date", cachename)
        cache.copy(dest)
        return

    logging.info("Downloading %s", url)
    try:
        CHUNK_SIZE = 4096
        with cache.open('wb') as f:
            while True:
                chunk = response.read(CHUNK_SIZE)
                if not chunk:
                    break
                f.write(chunk)
        response.close()
    except Exception as e:  # pragma: no cover
        try:
            cache.remove()
        except OSError:
            pass
        raise e

    cache.copy(dest)
