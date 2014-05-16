from __future__ import unicode_literals


def escape(s):
    return s.replace('\\', '\\\\').replace('"', '\\"')


class CommonEqualityMixin(object):
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

    KB = 1<<10
    MB = 1<<20
    GB = 1<<30
    TB = 1<<40
    PB = 1<<50

    nbytes = float(nbytes)

    if nbytes < KB:
        return "{} bytes".format(nbytes)
    elif nbytes < MB:
        return "{:.2f} KB".format(nbytes / KB)
    elif nbytes < GB:
        return "{:.2f} MB".format(nbytes / MB)
    elif nbytes < TB:
        return "{:.2f} GB".format(nbytes / GB)
    elif nbytes < PB:
        return "{:.2f} TB".format(nbytes / TB)
    else:
        return "{:.2f} PB".format(nbytes / PB)
