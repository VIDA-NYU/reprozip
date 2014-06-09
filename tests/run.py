from contextlib import contextmanager
import subprocess
import yaml
import sys

from reprounzip.unpackers.common import join_root
from rpaths import Path


@contextmanager
def in_temp_dir():
    tmp = Path.tempdir(prefix='reprozip_tests_')
    try:
        with tmp.in_dir():
            yield
    finally:
        tmp.rmtree(ignore_errors=True)


tests = Path(__file__).parent.absolute()


def build(target, *sources):
    subprocess.check_call(['cc', '-o', target] + [(tests / s).path
                                                  for s in sources])


if len(sys.argv) == 2 and sys.argv[1] == '--interactive':
    interactive = True
elif len(sys.argv) == 1:
    interactive = False
else:
    print("Usage: run.py [--interactive]")
    sys.exit(1)


with in_temp_dir():
    # Build
    build('simple', 'simple.c')
    # Trace
    subprocess.check_call(['reprozip', '-v', '-v', 'trace',
                           '-d', 'rpz-simple',
                           './simple',
                           (tests / 'simple_input.txt').path,
                           'simple_output.txt'])
    orig_output_location = Path('simple_output.txt').absolute()
    assert orig_output_location.is_file()
    with orig_output_location.open() as fp:
        assert fp.read().strip() == '42'
    orig_output_location.remove()
    # Read config
    with Path('rpz-simple/config.yml').open() as fp:
        conf = yaml.safe_load(fp)
    other_files = set(Path(f).absolute() for f in conf['other_files'])
    expected = [Path('simple'), (tests / 'simple_input.txt')]
    assert other_files.issuperset([f.absolute() for f in expected])
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
    output_in_dir = join_root(Path('simpledir/root'), orig_output_location)
    assert output_in_dir.is_file()
    with output_in_dir.open() as fp:
        assert fp.read().strip() == '42'
    output_in_dir.remove()
    # Unpack chroot
    subprocess.check_call(['reprounzip', '-v', '-v', 'chroot',
                           'simple.rpz', 'simplechroot'])
    # Run chroot
    subprocess.check_call(['sudo', 'sh', 'simplechroot/script.sh'])
    output_in_chroot = join_root(Path('simplechroot/root'),
                                 orig_output_location)
    assert output_in_chroot.is_file()
    with output_in_chroot.open() as fp:
        assert fp.read().strip() == '42'
    output_in_chroot.remove()

    if not Path('/vagrant').exists():
        subprocess.check_call(['sudo', 'sh', '-c',
                               'mkdir /vagrant; chmod 777 /vagrant'])

    # Unpack Vagrant-chroot
    subprocess.check_call(['reprounzip', '-v', '-v', 'vagrant', '--use-chroot',
                           'simple.rpz', '/vagrant/simplevagrantchroot'])
    print("\nVagrant project set up in simplevagrantchroot")
    try:
        if interactive:
            print("Test and press enter")
            sys.stdin.readline()
    finally:
        Path('/vagrant/simplevagrantchroot').rmtree()
    # Unpack usual Vagrant
    subprocess.check_call(['reprounzip', '-v', '-v', 'vagrant',
                           'simple.rpz', '/vagrant/simplevagrant'])
    print("\nVagrant project set up in simplevagrant")
    try:
        if interactive:
            print("Test and press enter")
            sys.stdin.readline()
    finally:
        Path('/vagrant/simplevagrant').rmtree()
