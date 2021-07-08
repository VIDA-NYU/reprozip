# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Utility functions.

These functions are shared between reprozip and reprounzip but are not specific
to this software (more utilities).
"""

import codecs
import contextlib
from datetime import datetime
import email.utils
import itertools
import locale
import logging
import operator
import os
from pathlib import Path, PurePosixPath
import requests
import shutil
import stat
import subprocess
import time


logger = logging.getLogger(__name__.split('.', 1)[0])


class StreamWriter(object):
    def __init__(self, stream):
        writer = codecs.getwriter(locale.getpreferredencoding())
        self._writer = writer(stream, 'replace')
        self.buffer = stream

    def writelines(self, lines):
        self.write(str('').join(lines))

    def write(self, obj):
        if isinstance(obj, bytes):
            self.buffer.write(obj)
        else:
            self._writer.write(obj)

    def __getattr__(self, name,
                    getattr=getattr):

        """ Inherit all other methods from the underlying stream.
        """
        return getattr(self._writer, name)


def flatten(n, iterable):
    """Flattens an iterable by repeatedly calling chain.from_iterable() on it.

    >>> a = [[1, 2, 3], [4, 5, 6]]
    >>> b = [[7, 8], [9, 10, 11, 12, 13, 14, 15, 16]]
    >>> l = [a, b]
    >>> list(flatten(0, a))
    [[1, 2, 3], [4, 5, 6]]
    >>> list(flatten(1, a))
    [1, 2, 3, 4, 5, 6]
    >>> list(flatten(1, l))
    [[1, 2, 3], [4, 5, 6], [7, 8], [9, 10, 11, 12, 13, 14, 15, 16]]
    >>> list(flatten(2, l))
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    """
    for _ in range(n):
        iterable = itertools.chain.from_iterable(iterable)
    return iterable


class UniqueNames(object):
    """Makes names unique amongst the ones it's already seen.
    """
    def __init__(self):
        self.names = set()

    def insert(self, name):
        assert name not in self.names
        self.names.add(name)

    def __call__(self, name):
        nb = 1
        attempt = name
        while attempt in self.names:
            nb += 1
            attempt = '%s_%d' % (name, nb)
        self.names.add(attempt)
        return attempt


def escape(s):
    """Escapes backslashes and double quotes in strings.

    This does NOT add quotes around the string.
    """
    return s.replace('\\', '\\\\').replace('"', '\\"')


def optional_return_type(req_args, other_args):
    """Sort of namedtuple but with name-only fields.

    When deconstructing a namedtuple, you have to get all the fields:

    >>> o = namedtuple('T', ['a', 'b', 'c'])(1, 2, 3)
    >>> a, b = o
    ValueError: too many values to unpack

    You thus cannot easily add new return values. This class allows it:

    >>> o2 = optional_return_type(['a', 'b'], ['c'])(1, 2, 3)
    >>> a, b = o2
    >>> c = o2.c
    """
    if len(set(req_args) | set(other_args)) != len(req_args) + len(other_args):
        raise ValueError

    # Maps argument name to position in each list
    req_args_pos = dict((n, i) for i, n in enumerate(req_args))
    other_args_pos = dict((n, i) for i, n in enumerate(other_args))

    def cstr(cls, *args, **kwargs):
        if len(args) > len(req_args) + len(other_args):
            raise TypeError(
                "Too many arguments (expected at least %d and no more than "
                "%d)" % (len(req_args),
                         len(req_args) + len(other_args)))

        args1, args2 = args[:len(req_args)], args[len(req_args):]
        req = dict((i, v) for i, v in enumerate(args1))
        other = dict(zip(other_args, args2))

        for k, v in kwargs.items():
            if k in req_args_pos:
                pos = req_args_pos[k]
                if pos in req:
                    raise TypeError("Multiple values for field %s" % k)
                req[pos] = v
            elif k in other_args_pos:
                if k in other:
                    raise TypeError("Multiple values for field %s" % k)
                other[k] = v
            else:
                raise TypeError("Unknown field name %s" % k)

        args = []
        for i, k in enumerate(req_args):
            if i not in req:
                raise TypeError("Missing value for field %s" % k)
            args.append(req[i])

        inst = tuple.__new__(cls, args)
        inst.__dict__.update(other)
        return inst

    dct = {'__new__': cstr}
    for i, n in enumerate(req_args):
        dct[n] = property(operator.itemgetter(i))
    return type(str('OptionalReturnType'), (tuple,), dct)


def tz_offset():
    offset = time.timezone if time.localtime().tm_isdst == 0 else time.altzone
    return -offset


def isodatetime():
    offset = tz_offset()
    sign = '+'
    if offset < 0:
        sign = '-'
        offset = -offset
    if offset % 60 == 0:
        offset = '%02d:%02d' % (offset // 3600, (offset // 60) % 60)
    else:
        offset = '%02d:%02d:%02d' % (offset // 3600, (offset // 60) % 60,
                                     offset % 60)
    # Remove microsecond
    now = datetime.now()
    now = datetime(year=now.year, month=now.month, day=now.day,
                   hour=now.hour, minute=now.minute, second=now.second)
    return '%s%s%s' % (now.isoformat(),
                       sign,
                       offset)


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


def normalize_path(path):
    """Normalize a path obtained from the database.
    """
    # For some reason, os.path.normpath() keeps multiple leading slashes
    # We don't want this since it has no meaning on Linux
    path = PurePosixPath(path)
    if str(path).startswith('//'):
        path = PurePosixPath(str(path)[1:])
    return path


def find_all_links_recursive(filename, files):
    path = Path('/')
    for c in filename.parts[1:]:
        # At this point, path is a canonical path, and all links in it have
        # been resolved

        # We add the next path component
        path = path / c

        # That component is possibly a link
        if path.is_symlink():
            # Adds the link itself
            files.add(path)

            target = Path(os.readlink(path))
            target = (path.parent / target).absolute()
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


def join_root(root, path):
    """Prepends `root` to the absolute path `path`.
    """
    path = str(path)
    assert path.startswith('/')
    path = path[1:]
    if path.startswith('/'):
        path = path[1:]
    return root / path


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
        for c in directory.parts[1:-1]:
            path = path / c
            sb = path.stat()
            if sb.st_uid == uid and not sb.st_mode & 0o100:
                logger.debug("Temporarily setting u+x on %s", path)
                restore_perms.append((path, sb.st_mode))
                path.chmod(sb.st_mode | 0o700)

        # Add u+wx to the target
        sb = directory.stat()
        if sb.st_uid == uid and sb.st_mode & 0o700 != 0o700:
            logger.debug("Temporarily setting u+wx on %s", directory)
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
    if path.is_symlink():
        raise OSError("Cannot call rmtree on a symbolic link")

    uid = os.getuid()
    st = path.lstat()

    if st.st_uid == uid and st.st_mode & 0o700 != 0o700:
        path.chmod(st.st_mode | 0o700)

    for entry in path.iterdir():
        if stat.S_ISDIR(entry.lstat().st_mode):
            rmtree_fixed(entry)
        else:
            entry.unlink()

    path.rmdir()


# Compatibility with ReproZip <= 1.0.3
check_output = subprocess.check_output


def download_file(url, dest, cachename=None, ssl_verify=None):
    """Downloads a file using a local cache.

    If the file cannot be downloaded or if it wasn't modified, the cached
    version will be used instead.

    The cache lives in ``~/.cache/reprozip/``.
    """
    if cachename is None:
        if dest is None:
            raise ValueError("One of 'dest' or 'cachename' must be specified")
        cachename = dest.name

    headers = {}

    if 'XDG_CACHE_HOME' in os.environ:
        cache = Path(os.environ['XDG_CACHE_HOME'])
    else:
        cache = Path('~/.cache').expanduser()
    cache = cache / 'reprozip' / cachename
    if cache.exists():
        mtime = email.utils.formatdate(cache.stat().st_mtime, usegmt=True)
        headers['If-Modified-Since'] = mtime

    cache.parent.mkdir(parents=True, exist_ok=True)

    try:
        response = requests.get(url, headers=headers,
                                timeout=2 if cache.exists() else 10,
                                stream=True, verify=ssl_verify)
        response.raise_for_status()
        if response.status_code == 304:
            raise requests.HTTPError(
                '304 File is up to date, no data returned',
                response=response)
    except requests.RequestException as e:
        if cache.exists():
            if e.response and e.response.status_code == 304:
                logger.info("Download %s: cache is up to date", cachename)
            else:
                logger.warning("Download %s: error downloading %s: %s",
                               cachename, url, e)
            if dest is not None:
                shutil.copy(cache, dest)
                return dest
            else:
                return cache
        else:
            raise

    logger.info("Download %s: downloading %s", cachename, url)
    try:
        with cache.open('wb') as f:
            for chunk in response.iter_content(4096):
                f.write(chunk)
        response.close()
    except Exception as e:  # pragma: no cover
        try:
            cache.unlink()
        except OSError:
            pass
        raise e
    logger.info("Downloaded %s successfully", cachename)

    if dest is not None:
        shutil.copy(cache, dest)
        return dest
    else:
        return cache
