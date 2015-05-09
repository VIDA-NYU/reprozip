#!/bin/sh

set -eux

case "$TEST_MODE"
in
    coverage)
        # Python
        if [ -f .coverage ]; then mv .coverage .coverage.orig; fi # FIXME: useless?
        coverage combine
        codecov

        # C
        # Find the coverage file (in distutils's build directory)
        OBJDIR=$(dirname "$(find . -name pytracer.gcno | head -n 1)")
        (cd reprozip/native && gcov -o ../../$OBJDIR *.c)
        curl -s -o - https://codecov.io/bash | bash -
        ;;
esac
