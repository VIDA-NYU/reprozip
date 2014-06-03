from contextlib import contextmanager
import os
import shutil
import subprocess
import tempfile
import yaml
import sys

from reprounzip.unpackers.common import join_root


@contextmanager
def in_temp_dir():
    tmp = tempfile.mkdtemp(prefix='reprozip_tests_')
    os.chdir(tmp)
    try:
        yield tmp
    finally:
        os.chdir('/')
        shutil.rmtree(tmp, ignore_errors=True)


tests = os.path.abspath(os.path.dirname(__file__))


def build(target, *sources):
    subprocess.check_call(['cc', '-o', target] + [os.path.join(tests, s)
                                                  for s in sources])


with in_temp_dir():
    # Build
    build('simple', 'simple.c')
    # Trace
    subprocess.check_call(['reprozip', '-v', '-v', 'trace',
                           '-d', 'rpz-simple',
                           './simple',
                           os.path.join(tests, 'simple_input.txt'),
                           'simple_output.txt'])
    orig_output_location = os.path.abspath('simple_output.txt')
    assert os.path.isfile(orig_output_location)
    with open(orig_output_location) as fp:
        assert fp.read().strip() == '42'
    os.remove(orig_output_location)
    # Read config
    with open('rpz-simple/config.yml') as fp:
        conf = yaml.safe_load(fp)
    other_files = set(os.path.abspath(f) for f in conf['other_files'])
    expected = ['simple', os.path.join(tests, 'simple_input.txt')]
    assert other_files.issuperset([os.path.abspath(f) for f in expected])
    # Pack
    subprocess.check_call(['reprozip', '-v', '-v', 'pack',
                           '-d', 'rpz-simple',
                           'simple.rpz'])
    # Unpack directory
    subprocess.check_call(['reprounzip', '-v', '-v', 'directory',
                           'simple.rpz', 'simpledir'])
    # Run script
    subprocess.check_call(['cat', 'simpledir/script.sh'])
    subprocess.check_call(['sh', 'simpledir/script.sh'])
    output_in_dir = join_root('simpledir/root', orig_output_location)
    assert os.path.isfile(output_in_dir)
    with open(output_in_dir) as fp:
        assert fp.read().strip() == '42'
    os.remove(output_in_dir)
    # Unpack chroot
    subprocess.check_call(['reprounzip', '-v', '-v', 'chroot',
                           'simple.rpz', 'simplechroot'])
    # Run chroot
    subprocess.check_call(['sudo', 'sh', 'simplechroot/script.sh'])
    output_in_chroot = join_root('simplechroot/root', orig_output_location)
    assert os.path.isfile(output_in_chroot)
    with open(output_in_chroot) as fp:
        assert fp.read().strip() == '42'
    os.remove(output_in_chroot)
    # Unpack Vagrant-chroot
    subprocess.check_call(['reprounzip', '-v', '-v', 'vagrant', '--use-chroot',
                           'simple.rpz', '/vagrant/simplevagrantchroot'])
    print("\nVagrant project set up in simplevagrantchroot\n"
          "Test and press enter")
    try:
        sys.stdin.readline()
    finally:
        shutil.rmtree('/vagrant/simplevagrantchroot')
    # Unpack usual Vagrant
    subprocess.check_call(['reprounzip', '-v', '-v', 'vagrant',
                           'simple.rpz', '/vagrant/simplevagrant'])
    print("\nVagrant project set up in simplevagrant\n"
          "Test and press enter")
    try:
        sys.stdin.readline()
    finally:
        shutil.rmtree('/vagrant/simplevagrant')
