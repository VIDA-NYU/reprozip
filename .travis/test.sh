#!/bin/sh

set -eux

export REPROZIP_USAGE_STATS=off

case "$TEST_MODE"
in
    run_program|coverage_c|coverage_py)
        export PYTHONUNBUFFERED=1
        if [ "$TEST_MODE" = "coverage_py" ]; then
            export COVER="coverage run --append --source=$PWD/reprozip/reprozip,$PWD/reprounzip/reprounzip,$PWD/reprounzip-docker/reprounzip,$PWD/reprounzip-vagrant/reprounzip,$PWD/reprounzip-vistrails/reprounzip --branch"
        fi
        if [ $TRAVIS_PYTHON_VERSION = "2.6" ]; then export REPROZIP_PYTHON=/tmp/rpz2.7/bin/python; fi
        python tests
        ;;
    check_style)
        flake8 --ignore=E126,E731 reprozip/reprozip reprounzip/reprounzip reprounzip-*/reprounzip
        ;;
    check_shared)
        diff -q reprozip/reprozip/common.py reprounzip/reprounzip/common.py
        diff -q reprozip/reprozip/utils.py reprounzip/reprounzip/utils.py
        ;;
esac
