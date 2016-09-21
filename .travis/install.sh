#!/bin/sh

set -eux

# Use a plain-ASCII locale, to make sure to catch stupid PY3 behaviors
export LANG=C
export LC_ALL=C

if [ -z "${XDG_CACHE_HOME-}" ]; then
    mkdir -p ~/.cache/reprozip
else
    mkdir -p "$XDG_CACHE_HOME/reprozip"
fi

case "$TEST_MODE"
in
    run_program|coverage)
        if [ "$TEST_MODE" = "coverage" ]; then
            export CFLAGS="-fprofile-arcs -ftest-coverage"
        fi
        sudo apt-get update -qq
        sudo apt-get install -qq libc6-dev-i386 gcc-multilib
        if [ $TEST_MODE = "coverage" ]; then
            pip install coverage codecov
            pip install -e ./reprozip -e ./reprounzip -e ./reprounzip-docker -e ./reprounzip-vagrant -e ./reprounzip-vistrails -e ./reprounzip-qt
        else
            pip install ./reprozip ./reprounzip ./reprounzip-docker ./reprounzip-vagrant ./reprounzip-vistrails ./reprounzip-qt
        fi
        ;;
    checks)
        pip install flake8
        ;;
esac
