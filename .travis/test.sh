#!/bin/sh

set -eux

export REPROZIP_USAGE_STATS=off

case "$TEST_MODE"
in
    run_program|coverage)
        export PYTHONUNBUFFERED=1
        if [ "$TEST_MODE" = "coverage" ]; then
            export COVER="coverage run --append --source=$PWD/reprozip/reprozip,$PWD/reprounzip/reprounzip,$PWD/reprounzip-docker/reprounzip,$PWD/reprounzip-vagrant/reprounzip,$PWD/reprounzip-vistrails/reprounzip --branch"
        fi
        if [ $TRAVIS_PYTHON_VERSION = "2.6" ]; then export REPROZIP_PYTHON=/tmp/rpz2.7/bin/python; fi
        python tests --run-docker
        ;;
    checks)
        flake8 reprozip/reprozip reprounzip/reprounzip reprounzip-*/reprounzip
        diff -q reprozip/reprozip/common.py reprounzip/reprounzip/common.py
        diff -q reprozip/reprozip/utils.py reprounzip/reprounzip/utils.py
        find reprozip reprounzip reprounzip-* .travis -name '*.py' -or -name '*.sh' -or -name '*.h' -or -name '*.c' | (set +x; while read i; do
            T=$(file -bi "$i")
            if ! ( echo "$T" | grep -q ascii || echo "$T" | grep -q empty ) ; then
                echo "$i is not ASCII"
                exit 1
            fi
        done)
        ;;
esac
