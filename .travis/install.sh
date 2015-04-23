#!/bin/sh

run_lines(){
    while read line; do echo "$line"; sh -c "$line" || exit $?; done
}

# Use a plain-ASCII locale, to make sure to catch stupid PY3 behaviors
export LANG=C
export LC_ALL=C

case "$TEST_MODE"
in
    run_program|coverage_c|coverage_py)
        if [ "$TEST_MODE" = "coverage_c" ]; then
            export CFLAGS="-fprofile-arcs -ftest-coverage"
        fi
        if [ $TRAVIS_PYTHON_VERSION = "2.6" ]; then
            run_lines<<'EOF'
            virtualenv -p python2.7 /tmp/rpz2.7
            /tmp/rpz2.7/bin/pip install 'git+https://github.com/remram44/rpaths.git#egg=rpaths'
            /tmp/rpz2.7/bin/pip install 'git+https://github.com/remram44/usagestats.git#egg=usagestats'
            /tmp/rpz2.7/bin/pip install ./reprozip
EOF
        fi
        run_lines<<'EOF'
        sudo apt-get update -qq
        sudo apt-get install -qq libc6-dev-i386 gcc-multilib
        pip install 'git+https://github.com/remram44/rpaths.git#egg=rpaths'
        pip install 'git+https://github.com/remram44/usagestats.git#egg=usagestats'
        if [ $TRAVIS_PYTHON_VERSION = "2.6" ]; then pip install unittest2; fi
        if [ $TEST_MODE = "coverage_c" ]; then pip install cpp-coveralls; fi
        if [ $TEST_MODE = "coverage_py" ]; then pip install coveralls; fi
        pip install ./reprozip ./reprounzip ./reprounzip-docker ./reprounzip-vagrant ./reprounzip-vistrails
EOF
        ;;
    check_style)
        pip install flake8
        ;;
esac
