#!/usr/bin/env python

# Copyright (C) 2014 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from contextlib import contextmanager
import os
from rpaths import Path, unicode
import subprocess
import sys
import yaml

from reprounzip.unpackers.common import join_root


tests = Path(__file__).parent.absolute()


if 'COVER' in os.environ:
    python = os.environ['COVER'].split(' ')
else:
    python = [sys.executable]

reprozip_main = tests.parent / 'reprozip/reprozip/main.py'
reprounzip_main = tests.parent / 'reprounzip/reprounzip/main.py'

programs = {
    'reprozip': python + [reprozip_main.absolute().path],
    'reprounzip': python + [reprounzip_main.absolute().path]}


@contextmanager
def in_temp_dir():
    tmp = Path.tempdir(prefix='reprozip_tests_')
    try:
        with tmp.in_dir():
            yield
    finally:
        tmp.rmtree(ignore_errors=True)


def check_call(args):
    print(" ".join(a if isinstance(a, unicode)
                   else a.decode('utf-8', 'replace')
                   for a in args))
    return subprocess.check_call(args)


def build(target, sources, args=[]):
    subprocess.check_call(['cc', '-o', target] +
                          [(tests / s).path
                           for s in sources] +
                          args)


if len(sys.argv) == 2 and sys.argv[1] == '--interactive':
    interactive = True
elif len(sys.argv) == 1:
    interactive = False
else:
    print("Usage: run.py [--interactive]")
    sys.exit(1)


with in_temp_dir():
    # ########################################
    # 'simple' program: trace, pack, unpack
    #

    # Build
    build('simple', ['simple.c'])
    # Trace
    check_call(programs['reprozip'] + ['-v', '-v', '-v', 'trace',
                                       '-d', 'rpz-simple',
                                       './simple',
                                       (tests / 'simple_input.txt').path,
                                       'simple_output.txt'])
    orig_output_location = Path('simple_output.txt').absolute()
    assert orig_output_location.is_file()
    with orig_output_location.open(encoding='utf-8') as fp:
        assert fp.read().strip() == '42'
    orig_output_location.remove()
    # Read config
    with Path('rpz-simple/config.yml').open(encoding='utf-8') as fp:
        conf = yaml.safe_load(fp)
    other_files = set(Path(f).absolute() for f in conf['other_files'])
    expected = [Path('simple'), (tests / 'simple_input.txt')]
    assert other_files.issuperset([f.resolve() for f in expected])
    # Pack
    check_call(programs['reprozip'] + ['-v', '-v', '-v', 'pack',
                                       '-d', 'rpz-simple',
                                       'simple.rpz'])
    # Unpack directory
    check_call(programs['reprounzip'] + ['-v', '-v', '-v', 'directory',
                                         'simple.rpz', 'simpledir'])
    # Run script
    check_call(['cat', 'simpledir/script.sh'])
    check_call(['sh', 'simpledir/script.sh'])
    output_in_dir = join_root(Path('simpledir/root'), orig_output_location)
    assert output_in_dir.is_file()
    with output_in_dir.open(encoding='utf-8') as fp:
        assert fp.read().strip() == '42'
    output_in_dir.remove()
    # Unpack chroot
    check_call(programs['reprounzip'] + ['-v', '-v', '-v', 'chroot',
                                         'simple.rpz', 'simplechroot'])
    # Run chroot
    check_call(['sudo', 'sh', 'simplechroot/script.sh'])
    output_in_chroot = join_root(Path('simplechroot/root'),
                                 orig_output_location)
    assert output_in_chroot.is_file()
    with output_in_chroot.open(encoding='utf-8') as fp:
        assert fp.read().strip() == '42'
    output_in_chroot.remove()

    if not Path('/vagrant').exists():
        check_call(['sudo', 'sh', '-c', 'mkdir /vagrant; chmod 777 /vagrant'])

    # Unpack Vagrant-chroot
    check_call(programs['reprounzip'] + ['-v', '-v', '-v', 'vagrant',
                                         '--use-chroot', 'simple.rpz',
                                         '/vagrant/simplevagrantchroot'])
    print("\nVagrant project set up in simplevagrantchroot")
    try:
        if interactive:
            print("Test and press enter")
            sys.stdin.readline()
    finally:
        Path('/vagrant/simplevagrantchroot').rmtree()
    # Unpack usual Vagrant
    check_call(programs['reprounzip'] + ['-v', '-v', '-v', 'vagrant',
                                         '--no-use-chroot', 'simple.rpz',
                                         '/vagrant/simplevagrant'])
    print("\nVagrant project set up in simplevagrant")
    try:
        if interactive:
            print("Test and press enter")
            sys.stdin.readline()
    finally:
        Path('/vagrant/simplevagrant').rmtree()

    # ########################################
    # 'threads' program: testrun
    #

    # Build
    build('threads', ['threads.c'], ['-lpthread'])
    # Trace
    check_call(programs['reprozip'] + ['-v', '-v', '-v',
                                       'testrun', './threads'])

    # ########################################
    # 'segv' program: testrun
    #

    # Build
    build('segv', ['segv.c'])
    # Trace
    check_call(programs['reprozip'] + ['-v', '-v', '-v', 'testrun', './segv'])

    # ########################################
    # 'exec_echo' program: testrun
    # This is built with -m32 so that we transition:
    #   python (x64) -> exec_echo (i386) -> echo (x64)
    #

    if sys.maxsize > 2 ** 32:
        # Build
        build('exec_echo', ['exec_echo.c'], ['-m32'])
        # Trace
        check_call(programs['reprozip'] + ['-v', '-v', '-v', 'testrun',
                                           './exec_echo'])
    else:
        print("Can't try exec_echo transitions: not running on 64bits")

    # ########################################
    # Copies back coverage report
    #

    coverage = Path('.coverage')
    if coverage.exists():
        coverage.copyfile(tests.parent / '.coverage.runpy')
