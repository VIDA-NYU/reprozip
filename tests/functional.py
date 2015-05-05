#!/usr/bin/env python

# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

import functools
import os
import re
from rpaths import Path, unicode
import subprocess
import sys
import yaml

from reprounzip.unpackers.common import join_root
from reprounzip.utils import iteritems, check_output as _check_output


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
    def wrapper(args):
        print("reprozip-tests$ " +
              " ".join(a if isinstance(a, unicode)
                       else a.decode('utf-8', 'replace')
                       for a in args))
        return f(args)
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
def check_output(args):
    output = _check_output(args)
    sys.stdout.buffer.write(output)
    return output


@print_arg_list
def check_errout(args):
    p = subprocess.Popen(args, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    sys.stderr.buffer.write(stderr)
    retcode = p.poll()
    if retcode:
        raise subprocess.CalledProcessError(retcode, args)
    return stderr


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
    input_files = conf['runs'][0]['input_files']
    assert (dict((k, Path(f).name)
                 for k, f in iteritems(input_files)) ==
            {'arg': b'simple_input.txt'})
    output_files = conf['runs'][0]['output_files']
    print(dict((k, Path(f).name) for k, f in iteritems(output_files)))
    # Here we don't test for dict equality, since we might have C coverage
    # files in the mix
    assert Path(output_files['arg']).name == b'simple_output.txt'
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
    check_call(rpuz + ['directory', 'run', 'simpledir'])
    output_in_dir = join_root(Path('simpledir/root'), orig_output_location)
    with output_in_dir.open(encoding='utf-8') as fp:
        assert fp.read().strip() == '42'
    # Delete with wrong command (should fail)
    p = subprocess.Popen(rpuz + ['chroot', 'destroy', 'simpledir'],
                         stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    assert p.poll() != 0
    stderr = stderr.splitlines()
    assert b"Wrong unpacker used" in stderr[0]
    assert stderr[1].startswith(b"usage: ")
    # Delete directory
    check_call(rpuz + ['directory', 'destroy', 'simpledir'])
    # Unpack chroot
    check_call(sudo + rpuz + ['chroot', 'setup', '--bind-magic-dirs',
                              'simple.rpz', 'simplechroot'])
    try:
        # Run chroot
        check_call(sudo + rpuz + ['chroot', 'run', 'simplechroot'])
        output_in_chroot = join_root(Path('simplechroot/root'),
                                     orig_output_location)
        with output_in_chroot.open(encoding='utf-8') as fp:
            assert fp.read().strip() == '42'
        # Get output file
        check_call(sudo + rpuz + ['chroot', 'download', 'simplechroot',
                                  'arg:output1.txt'])
        with Path('output1.txt').open(encoding='utf-8') as fp:
            assert fp.read().strip() == '42'
        # Replace input file
        check_call(sudo + rpuz + ['chroot', 'upload', 'simplechroot',
                                  '%s:arg' % (tests / 'simple_input2.txt')])
        check_call(sudo + rpuz + ['chroot', 'upload', 'simplechroot'])
        # Run again
        check_call(sudo + rpuz + ['chroot', 'run', 'simplechroot'])
        output_in_chroot = join_root(Path('simplechroot/root'),
                                     orig_output_location)
        with output_in_chroot.open(encoding='utf-8') as fp:
            assert fp.read().strip() == '36'
        # Delete with wrong command (should fail)
        p = subprocess.Popen(rpuz + ['directory', 'destroy', 'simplechroot'],
                             stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        assert p.poll() != 0
        stderr = stderr.splitlines()
        assert b"Wrong unpacker used" in stderr[0]
        assert stderr[1].startswith(b"usage:")
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
            check_call(rpuz + ['vagrant', 'run', '--no-stdin',
                               (tests / 'vagrant/simplevagrantchroot').path])
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
            check_call(rpuz + ['vagrant', 'run', '--no-stdin',
                               (tests / 'vagrant/simplevagrant').path])
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
            check_call(rpuz + ['docker', 'run', 'simpledocker'])
            # Get output file
            check_call(rpuz + ['docker', 'download', 'simpledocker',
                               'arg:doutput1.txt'])
            with Path('doutput1.txt').open(encoding='utf-8') as fp:
                assert fp.read().strip() == '42'
            # Replace input file
            check_call(rpuz + ['docker', 'upload', 'simpledocker',
                               '%s:arg' % (tests / 'simple_input2.txt')])
            check_call(rpuz + ['docker', 'upload', 'simpledocker'])
            check_call(rpuz + ['showfiles', 'simpledocker'])
            # Run again
            check_call(rpuz + ['docker', 'run', 'simpledocker'])
            # Get output file
            check_call(rpuz + ['docker', 'download', 'simpledocker',
                               'arg:doutput2.txt'])
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
    check_call(rpz + ['testrun', './threads'])

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
    stderr = check_errout(rpz + ['testrun', './connect'])
    stderr = stderr.split(b'\n')
    assert not any(b'program exited with non-zero code' in l for l in stderr)
    assert any(re.search(br'process connected to [0-9.]+:80', l)
               for l in stderr)

    # ########################################
    # Copies back coverage report
    #

    coverage = Path('.coverage')
    if coverage.exists():
        coverage.copyfile(tests.parent / '.coverage.runpy')
