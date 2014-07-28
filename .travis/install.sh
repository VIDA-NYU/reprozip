#!/bin/sh

run_lines(){
    while read line; do echo "$line"; sh -c "$line" || exit $?; done
}

case "$TEST_MODE"
in
    run_program|coverage_c)
        if [ "$TEST_MODE" = "coverage_c" ]; then
            export CFLAGS="-fprofile-arcs -ftest-coverage"
        fi
        run_lines<<'EOF'
        pip install 'git+https://github.com/remram44/rpaths.git#egg=rpaths'
        if [ $TEST_MODE = "coverage_c" ]; then pip install cpp-coveralls; fi
        cd reprozip && python setup.py install
        cd reprounzip && python setup.py install
        cd reprounzip-vagrant && python setup.py install
EOF
        ;;
    coverage_py)
        run_lines<<'EOF'
        pip install 'git+https://github.com/remram44/rpaths.git#egg=rpaths'
        pip install coveralls
        cd reprozip && python setup.py develop
        cd reprounzip && python setup.py develop
        cd reprounzip-vagrant && python setup.py develop
EOF
        ;;
    check_style)
        pip install flake8
        ;;
esac
