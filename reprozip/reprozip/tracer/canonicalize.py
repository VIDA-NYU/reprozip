import itertools
from rpaths import Path

from reprozip.common import File
from reprozip.tracer.linux_pkgs import identify_packages
from reprozip.tracer.trace import merge_files


def expand_patterns(patterns):
    files = set()
    dirs = set()

    # Finds all matching paths
    for pattern in patterns:
        for path in Path('/').recursedir(pattern):
            if path.is_dir():
                dirs.add(path)
            else:
                files.add(path)

    # Don't include directories whose files are included
    non_empty_dirs = set([Path('/')])
    for p in files | dirs:
        path = Path('/')
        for c in p.components[1:]:
            path = path / c
            non_empty_dirs.add(path)

    # Builds the final list
    return [File(p) for p in itertools.chain(dirs - non_empty_dirs, files)]


def canonicalize_config(runs, packages, other_files, additional_patterns,
                        sort_packages):
    add_files = expand_patterns(additional_patterns)
    if sort_packages:
        add_files, add_packages = identify_packages(add_files)
    else:
        add_packages = []
    other_files, packages = merge_files(add_files, add_packages,
                                        other_files, packages)
    return runs, packages, other_files
