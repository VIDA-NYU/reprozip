#!/bin/sh

set -eux

# Use a plain-ASCII locale, to make sure to catch stupid PY3 behaviors
export LANG=C
export LC_ALL=C

case "$TEST_MODE"
in
    run_program|coverage_c|coverage_py)
        if [ "$TEST_MODE" = "coverage_c" ]; then
            export CFLAGS="-fprofile-arcs -ftest-coverage"
        fi
        if [ $TRAVIS_PYTHON_VERSION = "2.6" ]; then
            virtualenv -p python2.7 /tmp/rpz2.7
            /tmp/rpz2.7/bin/pip install 'git+https://github.com/remram44/rpaths.git#egg=rpaths'
            /tmp/rpz2.7/bin/pip install 'git+https://github.com/remram44/usagestats.git#egg=usagestats'
            /tmp/rpz2.7/bin/pip install ./reprozip
        fi
        sudo apt-get update -qq
        sudo apt-get install -qq libc6-dev-i386 gcc-multilib
        pip install 'git+https://github.com/remram44/rpaths.git#egg=rpaths'
        pip install 'git+https://github.com/remram44/usagestats.git#egg=usagestats'
        if [ $TRAVIS_PYTHON_VERSION = "2.6" ]; then pip install unittest2; fi
        if [ $TEST_MODE = "coverage_py" -o $TEST_MODE = "coverage_c" ]; then
            pip install coverage codecov
            pip install -e ./reprozip -e ./reprounzip -e ./reprounzip-docker -e ./reprounzip-vagrant -e ./reprounzip-vistrails
        else
            pip install ./reprozip ./reprounzip ./reprounzip-docker ./reprounzip-vagrant ./reprounzip-vistrails
        fi
        ;;
    checks)
        pip install flake8
        ;;
esac
