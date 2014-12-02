#!/bin/sh

run_lines(){
    while read line; do echo "$line"; sh -c "$line" || exit $?; done
}

case "$TEST_MODE"
in
    run_program|coverage_c)
        export PYTHONUNBUFFERED=1
        if [ $TRAVIS_PYTHON_VERSION = "2.6" ]; then export REPROZIP_PYTHON=/usr/bin/python2.7; fi
        run_lines<<'EOF'
        reprozip testrun bash -c "cat ../../../../../etc/passwd;cd /var/lib;cat ../../etc/group"
        reprozip trace bash -c "cat /etc/passwd;echo"
        reprozip trace --continue sh -c "cat /etc/group;/usr/bin/id"
        reprounzip graph graph.dot
        reprozip pack
        reprounzip graph graph2.dot experiment.rpz
        python tests
EOF
        ;;
    coverage_py)
        export PYTHONUNBUFFERED=1
        export COVER="coverage run --append --source=$PWD/reprozip/reprozip,$PWD/reprounzip/reprounzip,$PWD/reprounzip-vagrant/reprounzip --branch"
        run_lines<<'EOF'
        $COVER reprozip/reprozip/main.py testrun bash -c "cat ../../../../../etc/passwd;cd /var/lib;cat ../../etc/group"
        $COVER reprozip/reprozip/main.py trace bash -c "cat /etc/passwd;echo"
        $COVER reprozip/reprozip/main.py trace --continue sh -c "cat /etc/group;/usr/bin/id"
        $COVER reprounzip/reprounzip/main.py graph graph.dot
        $COVER reprozip/reprozip/main.py pack
        $COVER reprounzip/reprounzip/main.py graph graph2.dot experiment.rpz
        python tests
EOF
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
