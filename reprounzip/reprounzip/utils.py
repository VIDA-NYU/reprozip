from __future__ import unicode_literals

import os


def escape(s):
    return s.replace('\\', '\\\\').replace('"', '\\"')


class CommonEqualityMixin(object):
    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)

    def __ne__(self, other):
        return not self.__eq__(other)


def find_all_links_recursive(filename, files):
    # We assume that filename is an abspath, so we can just split on os.sep
    path = '/'
    for c in filename.split(os.sep)[1:]:
        # At this point, path is a canonical path, and all links in it have
        # been resolved

        # We add the next path component
        path = os.path.join(path, c)

        # That component is possibly a link
        if os.path.islink(path):
            target = os.path.abspath(os.path.join(os.path.dirname(path),
                                                  os.readlink(path)))
            # Here, target might contain a number of symlinks
            if target not in files:
                # Adds the link itself
                files.add(path)

                # Recurse on this new path
                find_all_links_recursive(target, files)
            # Restores the invariant; realpath might resolve several links here
            path = os.path.realpath(path)
    return path


def find_all_links(filename):
    """Dereferences symlinks from a path, returning them plus the final target.

    Example:
        /
            a -> b
            b
                g -> c
                c -> ../a/d
                d
                    e -> /f
            f
    >>> find_all_links('/a/g/e')
    ['/a', '/b/c', '/b/g', '/b/d/e', '/f']
    """
    files = set()
    path = find_all_links_recursive(filename, files)
    return list(files) + [path]
