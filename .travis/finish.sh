#!/bin/sh

set -eux

case "$TEST_MODE"
in
    coverage_py)
        if [ -f .coverage ]; then mv .coverage .coverage.orig; fi # FIXME: useless?
        coverage combine
        codecov
        ;;
    coverage_c)
        gcov reprozip/native/*.c
        curl -s -o - https://codecov.io/bash | bash -
        ;;
esac
