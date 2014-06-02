#!/bin/sh

case "$TEST_MODE"
in
    run_program)
        (while read line; do echo "$line"; sh -c "$line" || exit $?; done)<<'EOF'
        cd reprozip && python setup.py install
        cd reprounzip && python setup.py install
        cd reprounzip-vagrant && python setup.py install
EOF
        ;;
    check_style)
        pip install flake8
        ;;
esac
