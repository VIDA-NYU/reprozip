#!/usr/bin/env python

# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import unicode_literals

import functools
import os
import re
from rpaths import Path, unicode
import subprocess
import sys
import yaml

from reprounzip.unpackers.common import join_root
from reprounzip.utils import stderr_bytes, stderr


tests = Path(__file__).parent.absolute()


def in_temp_dir(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        tmp = Path.tempdir(prefix='reprozip_tests_')
        try:
            with tmp.in_dir():
                return f(*args, **kwargs)
        finally:
            tmp.rmtree(ignore_errors=True)
    return wrapper


def print_arg_list(f):
    """Decorator printing the sole argument (list of strings) first.
    """
    @functools.wraps(f)
    def wrapper(arglist, *args, **kwargs):
        print("\nreprozip-tests$ " +
              " ".join(a if isinstance(a, unicode)
                       else a.decode('utf-8', 'replace')
                       for a in arglist))
        return f(arglist, *args, **kwargs)
    return wrapper


@print_arg_list
def call(args):
    r = subprocess.call(args)
    print("---> %d" % r)
    return r


@print_arg_list
def check_call(args):
    return subprocess.check_call(args)


@print_arg_list
def check_output(args, stream='out'):
    if stream == 'out':
        kw = {'stdout': subprocess.PIPE}
    elif stream == 'err':
        kw = {'stderr': subprocess.PIPE}
    else:
        raise ValueError
    p = subprocess.Popen(args, **kw)
    if stream == 'out':
        fp = p.stdout
    else:
        fp = p.stderr
    output = []
    while True:
        line = fp.readline()
        if not line:
            break
        stderr_bytes.write(line)
        output.append(line)
    retcode = p.wait()
    if retcode != 0:
        raise subprocess.CalledProcessError(retcode, args)
    return b''.join(output)


def build(target, sources, args=[]):
    check_call(['/usr/bin/env', 'CFLAGS=', 'cc', '-o', target] +
               [(tests / s).path
                for s in sources] +
               args)


@in_temp_dir
def functional_tests(raise_warnings, interactive, run_vagrant, run_docker):
    # Tests on Python < 2.7.3: need to use separate reprozip Python (with known
    # working version of Python)
    if sys.version_info < (2, 7, 3):
        bug13676 = True
        if 'REPROZIP_PYTHON' not in os.environ:
            sys.stderr.write("Error: using reprozip with Python %s!\n" %
                             sys.version.split(' ', 1)[0])
            sys.exit(1)
    else:
        bug13676 = False

    rpz = [os.environ.get('REPROZIP_PYTHON', sys.executable)]
    rpuz = [os.environ.get('REPROUNZIP_PYTHON', sys.executable)]

    # Can't match on the SignalWarning category here because of a Python bug
    # http://bugs.python.org/issue22543
    if raise_warnings:
        rpz.extend(['-W', 'error:signal'])
        rpuz.extend(['-W', 'error:signal'])

    if 'COVER' in os.environ:
        rpz.extend(['-m'] + os.environ['COVER'].split(' '))
        rpuz.extend(['-m'] + os.environ['COVER'].split(' '))

    reprozip_main = tests.parent / 'reprozip/reprozip/main.py'
    reprounzip_main = tests.parent / 'reprounzip/reprounzip/main.py'

    verbose = ['-v'] * 3
    rpz.extend([reprozip_main.absolute().path] + verbose)
    rpuz.extend([reprounzip_main.absolute().path] + verbose)

    print("Command lines are:\n%r\n%r" % (rpz, rpuz))

    # ########################################
    # testrun /bin/echo
    #

    output = check_output(rpz + ['testrun', '/bin/echo', 'outputhere'])
    assert any(b' 1 | /bin/echo outputhere ' in l
               for l in output.splitlines())

    output = check_output(rpz + ['testrun', '-a', '/fake/path/echo',
                                 '/bin/echo', 'outputhere'])
    assert any(b' 1 | (/bin/echo) /fake/path/echo outputhere ' in l
               for l in output.splitlines())

    # ########################################
    # testrun multiple commands
    #

    check_call(rpz + ['testrun', 'bash', '-c',
                      'cat ../../../../../etc/passwd;'
                      'cd /var/lib;'
                      'cat ../../etc/group'])
    check_call(rpz + ['trace',
                      'bash', '-c', 'cat /etc/passwd;echo'])
    check_call(rpz + ['trace', '--continue',
                      'sh', '-c', 'cat /etc/group;/usr/bin/id'])
    check_call(rpz + ['pack'])
    if not bug13676:
        check_call(rpuz + ['graph', 'graph.dot'])
        check_call(rpuz + ['graph', 'graph2.dot', 'experiment.rpz'])

    sudo = ['sudo', '-E']  # -E to keep REPROZIP_USAGE_STATS

    # ########################################
    # 'simple' program: trace, pack, info, unpack
    #

    def check_simple(args, stream, infile=1):
        output = check_output(args, stream).splitlines()
        try:
            first = output.index(b"Read 6 bytes")
        except ValueError:
            stderr.write("output = %r\n" % output)
            raise
        if infile == 1:
            assert output[first + 1] == b"a = 29, b = 13"
            assert output[first + 2] == b"result = 42"
        else:  # infile == 2
            assert output[first + 1] == b"a = 25, b = 11"
            assert output[first + 2] == b"result = 36"

    # Build
    build('simple', ['simple.c'])
    # Trace
    check_call(rpz + ['trace', '-d', 'rpz-simple',
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
    # Check input and output files
    inputs_outputs = conf['inputs_outputs']
    # Exactly one input: "arg1", "...simple_input.txt"
    # Output: 'arg2', "...simple_output.txt"
    # There might be more output files: the C coverage files
    found = 0
    for fdict in inputs_outputs:
        if Path(fdict['path']).name == b'simple_input.txt':
            assert fdict['name'] == 'arg1'
            assert fdict['read_by_runs'] == [0]
            assert not fdict.get('written_by_runs')
            found |= 0x01
        elif Path(fdict['path']).name == b'simple_output.txt':
            assert fdict['name'] == 'arg2'
            assert not fdict.get('read_by_runs')
            assert fdict['written_by_runs'] == [0]
            found |= 0x02
        else:
            # No other inputs
            assert not fdict.get('read_by_runs')
    assert found == 0x03
    # Pack
    check_call(rpz + ['pack', '-d', 'rpz-simple', 'simple.rpz'])
    Path('simple').remove()
    # Info
    check_call(rpuz + ['info', 'simple.rpz'])
    # Show files
    check_call(rpuz + ['showfiles', 'simple.rpz'])
    # Lists packages
    check_call(rpuz + ['installpkgs', '--summary', 'simple.rpz'])
    # Unpack directory
    check_call(rpuz + ['directory', 'setup', 'simple.rpz', 'simpledir'])
    # Run directory
    check_simple(rpuz + ['directory', 'run', 'simpledir'], 'err')
    output_in_dir = join_root(Path('simpledir/root'), orig_output_location)
    with output_in_dir.open(encoding='utf-8') as fp:
        assert fp.read().strip() == '42'
    # Delete with wrong command (should fail)
    p = subprocess.Popen(rpuz + ['chroot', 'destroy', 'simpledir'],
                         stderr=subprocess.PIPE)
    out, err = p.communicate()
    assert p.poll() != 0
    err = err.splitlines()
    assert b"Wrong unpacker used" in err[0]
    assert err[1].startswith(b"usage: ")
    # Delete directory
    check_call(rpuz + ['directory', 'destroy', 'simpledir'])
    # Unpack chroot
    check_call(sudo + rpuz + ['chroot', 'setup', '--bind-magic-dirs',
                              'simple.rpz', 'simplechroot'])
    try:
        # Run chroot
        check_simple(sudo + rpuz + ['chroot', 'run', 'simplechroot'], 'err')
        output_in_chroot = join_root(Path('simplechroot/root'),
                                     orig_output_location)
        with output_in_chroot.open(encoding='utf-8') as fp:
            assert fp.read().strip() == '42'
        # Get output file
        check_call(sudo + rpuz + ['chroot', 'download', 'simplechroot',
                                  'arg2:output1.txt'])
        with Path('output1.txt').open(encoding='utf-8') as fp:
            assert fp.read().strip() == '42'
        # Replace input file
        check_call(sudo + rpuz + ['chroot', 'upload', 'simplechroot',
                                  '%s:arg1' % (tests / 'simple_input2.txt')])
        check_call(sudo + rpuz + ['chroot', 'upload', 'simplechroot'])
        # Run again
        check_simple(sudo + rpuz + ['chroot', 'run', 'simplechroot'], 'err', 2)
        output_in_chroot = join_root(Path('simplechroot/root'),
                                     orig_output_location)
        with output_in_chroot.open(encoding='utf-8') as fp:
            assert fp.read().strip() == '36'
        # Delete with wrong command (should fail)
        p = subprocess.Popen(rpuz + ['directory', 'destroy', 'simplechroot'],
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        assert p.poll() != 0
        err = err.splitlines()
        assert b"Wrong unpacker used" in err[0]
        assert err[1].startswith(b"usage:")
    finally:
        # Delete chroot
        check_call(sudo + rpuz + ['chroot', 'destroy', 'simplechroot'])

    if not (tests / 'vagrant').exists():
        check_call(['sudo', 'sh', '-c',
                    'mkdir %(d)s; chmod 777 %(d)s' % {'d': tests / 'vagrant'}])

    # Unpack Vagrant-chroot
    check_call(rpuz + ['vagrant', 'setup/create', '--use-chroot', 'simple.rpz',
                       (tests / 'vagrant/simplevagrantchroot').path])
    print("\nVagrant project set up in simplevagrantchroot")
    try:
        if run_vagrant:
            check_simple(rpuz + ['vagrant', 'run', '--no-stdin',
                                 (tests / 'vagrant/simplevagrantchroot').path],
                         'out')
            # Get output file
            check_call(rpuz + ['vagrant', 'download',
                               (tests / 'vagrant/simplevagrantchroot').path,
                               'arg2:voutput1.txt'])
            with Path('voutput1.txt').open(encoding='utf-8') as fp:
                assert fp.read().strip() == '42'
            # Replace input file
            check_call(rpuz + ['vagrant', 'upload',
                               (tests / 'vagrant/simplevagrantchroot').path,
                               '%s:arg1' % (tests / 'simple_input2.txt')])
            check_call(rpuz + ['vagrant', 'upload',
                               (tests / 'vagrant/simplevagrantchroot').path])
            # Run again
            check_simple(rpuz + ['vagrant', 'run', '--no-stdin',
                                 (tests / 'vagrant/simplevagrantchroot').path],
                         'out', 2)
            # Get output file
            check_call(rpuz + ['vagrant', 'download',
                               (tests / 'vagrant/simplevagrantchroot').path,
                               'arg2:voutput2.txt'])
            with Path('voutput2.txt').open(encoding='utf-8') as fp:
                assert fp.read().strip() == '36'
            # Destroy
            check_call(rpuz + ['vagrant', 'destroy',
                               (tests / 'vagrant/simplevagrantchroot').path])
        elif interactive:
            print("Test and press enter")
            sys.stdin.readline()
    finally:
        if (tests / 'vagrant/simplevagrantchroot').exists():
            (tests / 'vagrant/simplevagrantchroot').rmtree()
    # Unpack Vagrant without chroot
    check_call(rpuz + ['vagrant', 'setup/create', '--dont-use-chroot',
                       'simple.rpz',
                       (tests / 'vagrant/simplevagrant').path])
    print("\nVagrant project set up in simplevagrant")
    try:
        if run_vagrant:
            check_simple(rpuz + ['vagrant', 'run', '--no-stdin',
                                 (tests / 'vagrant/simplevagrant').path],
                         'out')
            # Get output file
            check_call(rpuz + ['vagrant', 'download',
                               (tests / 'vagrant/simplevagrant').path,
                               'arg2:woutput1.txt'])
            with Path('woutput1.txt').open(encoding='utf-8') as fp:
                assert fp.read().strip() == '42'
            # Replace input file
            check_call(rpuz + ['vagrant', 'upload',
                               (tests / 'vagrant/simplevagrant').path,
                               '%s:arg1' % (tests / 'simple_input2.txt')])
            check_call(rpuz + ['vagrant', 'upload',
                               (tests / 'vagrant/simplevagrant').path])
            # Run again
            check_simple(rpuz + ['vagrant', 'run', '--no-stdin',
                                 (tests / 'vagrant/simplevagrant').path],
                         'out', 2)
            # Get output file
            check_call(rpuz + ['vagrant', 'download',
                               (tests / 'vagrant/simplevagrant').path,
                               'arg2:woutput2.txt'])
            with Path('woutput2.txt').open(encoding='utf-8') as fp:
                assert fp.read().strip() == '36'
            # Destroy
            check_call(rpuz + ['vagrant', 'destroy',
                               (tests / 'vagrant/simplevagrant').path])
        elif interactive:
            print("Test and press enter")
            sys.stdin.readline()
    finally:
        if (tests / 'vagrant/simplevagrant').exists():
            (tests / 'vagrant/simplevagrant').rmtree()

    # Unpack Docker
    check_call(rpuz + ['docker', 'setup/create', 'simple.rpz', 'simpledocker'])
    print("\nDocker project set up in simpledocker")
    try:
        if run_docker:
            check_call(rpuz + ['docker', 'setup/build', 'simpledocker'])
            check_simple(rpuz + ['docker', 'run', 'simpledocker'], 'out')
            # Get output file
            check_call(rpuz + ['docker', 'download', 'simpledocker',
                               'arg2:doutput1.txt'])
            with Path('doutput1.txt').open(encoding='utf-8') as fp:
                assert fp.read().strip() == '42'
            # Replace input file
            check_call(rpuz + ['docker', 'upload', 'simpledocker',
                               '%s:arg1' % (tests / 'simple_input2.txt')])
            check_call(rpuz + ['docker', 'upload', 'simpledocker'])
            check_call(rpuz + ['showfiles', 'simpledocker'])
            # Run again
            check_simple(rpuz + ['docker', 'run', 'simpledocker'], 'out', 2)
            # Get output file
            check_call(rpuz + ['docker', 'download', 'simpledocker',
                               'arg2:doutput2.txt'])
            with Path('doutput2.txt').open(encoding='utf-8') as fp:
                assert fp.read().strip() == '36'
            # Destroy
            check_call(rpuz + ['docker', 'destroy', 'simpledocker'])
        elif interactive:
            print("Test and press enter")
            sys.stdin.readline()
    finally:
        if Path('simpledocker').exists():
            Path('simpledocker').rmtree()

    # ########################################
    # 'threads' program: testrun
    #

    # Build
    build('threads', ['threads.c'], ['-lpthread'])
    # Trace
    output = check_output(rpz + ['testrun', './threads'], 'err')
    assert any(b'successfully exec\'d /bin/./echo' in l
               for l in output.splitlines())

    # ########################################
    # 'threads2' program: testrun
    #

    # Build
    build('threads2', ['threads2.c'], ['-lpthread'])
    # Trace
    output = check_output(rpz + ['testrun', './threads2'], 'err')
    assert any(b'successfully exec\'d /bin/echo' in l
               for l in output.splitlines())

    # ########################################
    # 'segv' program: testrun
    #

    # Build
    build('segv', ['segv.c'])
    # Trace
    check_call(rpz + ['testrun', './segv'])

    # ########################################
    # 'exec_echo' program: trace, pack, run --cmdline
    #

    # Build
    build('exec_echo', ['exec_echo.c'])
    # Trace
    check_call(rpz + ['trace', './exec_echo', 'originalexecechooutput'])
    # Pack
    check_call(rpz + ['pack', 'exec_echo.rpz'])
    # Unpack chroot
    check_call(sudo + rpuz + ['chroot', 'setup',
                              'exec_echo.rpz', 'echochroot'])
    try:
        # Run original command-line
        output = check_output(sudo + rpuz + ['chroot', 'run',
                                             'echochroot'])
        assert output == b'originalexecechooutput\n'
        # Prints out command-line
        output = check_output(sudo + rpuz + ['chroot', 'run',
                                             'echochroot', '--cmdline'])
        assert any(b'./exec_echo originalexecechooutput' == s.strip()
                   for s in output.split(b'\n'))
        # Run with different command-line
        output = check_output(sudo + rpuz + [
                'chroot', 'run', 'echochroot',
                '--cmdline', './exec_echo', 'changedexecechooutput'])
        assert output == b'changedexecechooutput\n'
    finally:
        check_call(sudo + rpuz + ['chroot', 'destroy', 'echochroot'])

    # ########################################
    # 'exec_echo' program: testrun
    # This is built with -m32 so that we transition:
    #   python (x64) -> exec_echo (i386) -> echo (x64)
    #

    if sys.maxsize > 2 ** 32:
        # Build
        build('exec_echo32', ['exec_echo.c'], ['-m32'])
        # Trace
        check_call(rpz + ['testrun', './exec_echo32 42'])
    else:
        print("Can't try exec_echo transitions: not running on 64bits")

    # ########################################
    # Tracing non-existing program
    #

    check_call(rpz + ['testrun', './doesntexist'])

    # ########################################
    # 'connect' program: testrun
    #

    # Build
    build('connect', ['connect.c'])
    # Trace
    err = check_output(rpz + ['testrun', './connect'], 'err')
    err = err.split(b'\n')
    assert not any(b'program exited with non-zero code' in l for l in err)
    assert any(re.search(br'process connected to [0-9.]+:80', l)
               for l in err)

    # ########################################
    # 'vfork' program: testrun
    #

    # Build
    build('vfork', ['vfork.c'])
    # Trace
    err = check_output(rpz + ['testrun', './vfork'], 'err')
    err = err.split(b'\n')
    assert not any(b'program exited with non-zero code' in l for l in err)

    # ########################################
    # Copies back coverage report
    #

    coverage = Path('.coverage')
    if coverage.exists():
        coverage.copyfile(tests.parent / '.coverage.runpy')
