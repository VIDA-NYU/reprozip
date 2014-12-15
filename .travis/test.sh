#!/bin/sh

run_lines(){
    while read line; do echo "$line"; sh -c "$line" || exit $?; done
}

export REPROZIP_USAGE_STATS=off

case "$TEST_MODE"
in
    run_program|coverage_c)
        export PYTHONUNBUFFERED=1
        if [ $TRAVIS_PYTHON_VERSION = "2.6" ]; then export REPROZIP_PYTHON=/tmp/rpz2.7/bin/python; fi
        python tests
        ;;
    coverage_py)
        export PYTHONUNBUFFERED=1
        export COVER="coverage run --append --source=$PWD/reprozip/reprozip,$PWD/reprounzip/reprounzip,$PWD/reprounzip-vagrant/reprounzip --branch"
        python tests
        ;;
    check_style)
        run_lines<<'EOF'
        flake8 --ignore=E126 reprozip/reprozip reprounzip/reprounzip reprounzip-*/reprounzip
EOF
        ;;
    check_shared)
        run_lines<<'EOF'
        diff -q reprozip/reprozip/common.py reprounzip/reprounzip/common.py
        diff -q reprozip/reprozip/utils.py reprounzip/reprounzip/utils.py
EOF
        ;;
esac
