#!/bin/sh

case "$TEST_MODE"
in
    coverage_py)
        if [ -f .coverage ]; then mv .coverage .coverage.orig; fi # FIXME: useless?
        coverage combine
        python -c "import coveralls.cli; coveralls.cli.main()"
        ;;
    coverage_c)
        python -c "import cpp_coveralls; cpp_coveralls.run()" --verbose --build-root "$PWD/reprozip"
        ;;
esac
