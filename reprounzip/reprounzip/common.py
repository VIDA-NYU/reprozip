import os
import yaml

from reprounzip.utils import CommonEqualityMixin


FILE_READ = 0x01
FILE_WRITE = 0x02
FILE_WDIR = 0x04


class File(CommonEqualityMixin):
    """A file, used at some point during the experiment.
    """
    def __init__(self, path):
        self.path = path
        try:
            stat = os.stat(path)
        except OSError:
            self.size = None
        else:
            self.size = stat.st_size

    def __eq__(self, other):
        return (isinstance(other, File) and
                self.path == other.path)

    def __hash__(self):
        return hash(self.path)


class Package(CommonEqualityMixin):
    def __init__(self, name, version, files=[], packfiles=True, size=None):
        self.name = name
        self.version = version
        self.files = list(files)
        self.packfiles = packfiles
        self.size = size

    def add_file(self, filename):
        self.files.append(filename)

    def __unicode__(self):
        return '%s (%s)' % (self.name, self.version)
    __str__ = __unicode__


class InvalidConfig(ValueError):
    """Configuration file is invalid.
    """


def read_files(files, File=File):
    return [File(f) for f in files]


def read_packages(packages, File=File, Package=Package):
    new_pkgs = []
    for pkg in packages:
        pkg['files'] = read_files(pkg['files'], File)
        new_pkgs.append(Package(**pkg))
    return new_pkgs


def load_config(filename, File=File, Package=Package):
    with open(filename) as fp:
        config = yaml.safe_load(fp)

    keys_ = set(config.keys())
    if 'version' not in keys_:
        raise InvalidConfig("Missing version")
    elif config['version'] != '0.0':
        raise InvalidConfig("Unknown version")
    elif not keys_.issubset(set(['version', 'runs',
                                 'packages', 'other_files'])):
        raise InvalidConfig("Unrecognized sections")

    runs = config.get('runs', [])
    packages = read_packages(config.get('packages', []), File, Package)
    other_files = read_files(config.get('other_files', []), File)

    return runs, packages, other_files
