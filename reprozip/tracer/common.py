import os

from reprozip.utils import CommonEqualityMixin, Serializable, hsize


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


class Package(CommonEqualityMixin, Serializable):
    def __init__(self, name, version, files=[], packfiles=True, size=None):
        self.name = name
        self.version = version
        self.files = list(files)
        self.packfiles = packfiles
        self.size = size

    def add_file(self, filename):
        self.files.append(filename)

    def serialize(self, fp, lvl=0):
        fp.write("Package(name=%s%s, size=%d,\n" % (
                 self.string(self.name),
                 ", version=%s" % self.string(self.version)
                 if self.version is not None else '',
                 self.size))
        fp.write('    ' * lvl + "        packfiles=%s,\n" %
                 ('True' if self.packfiles else 'False'))
        fp.write('    ' * lvl + "        files=[\n")
        fp.write('    ' * (lvl + 1) + "# Total files used: %s\n" %
                 hsize(sum(f.size for f in self.files if f.size is not None)))
        fp.write('    ' * (lvl + 1) + "# Installed package size: %s\n" %
                 hsize(self.size))
        for f in self.files:
            fp.write('    ' * (lvl + 1))
            f.serialize(fp, lvl + 1)
            fp.write(', # %s\n' % hsize(f.size))
        fp.write('    ' * lvl + '])')
