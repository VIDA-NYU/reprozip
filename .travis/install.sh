#!/bin/sh

case "$TEST_MODE"
in
    run_program)
        python setup.py install
        ;;
    check_style)
        pip install flake8
        ;;
esac
