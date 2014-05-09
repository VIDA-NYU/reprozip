from __future__ import unicode_literals


def compat_execfile(filename, globals=None, locals=None):
    with open(filename) as fp:
        exec(fp.read(), globals, locals)


class Serializable(object):
    """Base class for things to be serialized.
    """
    @staticmethod
    def line(fp, line, lvl=0):
        fp.write(b'    ' * lvl + line + b'\n')

    @staticmethod
    def string(s):
        s = repr(s)
        if s[0] == 'u' or s[0] == 'b':
            return s[1:]
        return s

    def serialize(self, fp, lvl=0):
        raise NotImplementedError


class CommonEqualityMixin(object):
    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)

    def __ne__(self, other):
        return not self.__eq__(other)
