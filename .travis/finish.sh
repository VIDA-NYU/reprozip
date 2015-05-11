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
        python -c "import cpp_coveralls; cpp_coveralls.run()" --verbose --build-root "$PWD/reprozip"
        ;;
esac
