#!/bin/sh

set -eux

export REPROZIP_USAGE_STATS=off
export REPROZIP_PARAMETERS=https://reprozip-stats.poly.edu/parameters/travis/

case "$TEST_MODE"
in
    run_program|coverage)
        export PYTHONUNBUFFERED=1
        if [ "$TEST_MODE" = "coverage" ]; then
            export COVER="coverage run --append --source=$PWD/reprozip/reprozip,$PWD/reprounzip/reprounzip,$PWD/reprounzip-docker/reprounzip,$PWD/reprounzip-vagrant/reprounzip,$PWD/reprounzip-vistrails/reprounzip --branch"
        fi
        python tests --run-docker
        ;;
    checks)
        flake8 --ignore=E731,W504 reprozip/reprozip reprounzip/reprounzip reprounzip-*/reprounzip reprounzip-qt/reprounzip_qt reprozip-jupyter/reprozip_jupyter tests/*.py
        find scripts -name '*.py' -exec flake8 {} +
        diff -q reprozip/reprozip/common.py reprounzip/reprounzip/common.py
        diff -q reprozip/reprozip/utils.py reprounzip/reprounzip/utils.py
        find reprozip reprounzip reprozip-* reprounzip-* .travis -name '*.py' -or -name '*.sh' -or -name '*.h' -or -name '*.c' | (set +x; while read i; do
            T=$(file -b --mime "$i")
            if ! ( echo "$T" | grep -q ascii || echo "$T" | grep -q empty ) ; then
                echo "$i is not ASCII"
                exit 1
            fi
        done)
        find reprozip reprounzip reprozip-* reprounzip-* -name '*.py' -exec sh -c "grep 'logging\\.\\(debug\\|warning\\|critical\\|error\\|info\\)' \"\$@\" && exit 1; exit 0" {} +
        for pkg in reprozip reprounzip reprozip-* reprounzip-*; do
            (cd $pkg && python setup.py check -r -s)
        done
        ;;
esac
