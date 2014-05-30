from contextlib import contextmanager
import os
import shutil
import subprocess
import tempfile
import yaml
import sys


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
    assert os.path.isfile('simple_output.txt')
    with open('simple_output.txt') as fp:
        assert fp.read().strip() == '42'
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
    # Unpack chroot
    subprocess.check_call(['reprounzip', '-v', '-v', 'chroot',
                           'simple.rpz', 'simplechroot'])
    # Run chroot
    subprocess.check_call(['sudo', 'sh', 'simplechroot/script.sh'])
    assert os.path.isfile('simple_output.txt')
    with open(os.path.join('simplechroot/root',
                           os.getcwd(),
                           'simple_output.txt')) as fp:
        assert fp.read().strip() == '42'
    # Unpack Vagrant-chroot
    subprocess.check_call(['reprounzip', '-v', '-v', 'vagrant', '--use-chroot',
                           'simple.rpz', '/vagrant/simplevagrantchroot'])
    print("\nVagrant project set up in simplevagrantchroot\n"
          "Test and press enter")
    sys.stdin.readline()
    shutil.rmtree('/vagrant/simplevagrantchroot')
    # Unpack usual Vagrant
    subprocess.check_call(['reprounzip', '-v', '-v', 'vagrant',
                           'simple.rpz', '/vagrant/simplevagrant'])
    print("\nVagrant project set up in simplevagrant\n"
          "Test and press enter")
    sys.stdin.readline()
    shutil.rmtree('/vagrant/simplevagrant')
