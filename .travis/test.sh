#!/bin/sh

run_lines(){
    while read line; do echo "$line"; sh -c "$line" || exit $?; done
}

case "$TEST_MODE"
in
    run_program)
        run_lines<<'EOF'
        reprozip testrun bash -c "cat ../../../../../etc/passwd;cd /var/lib;cat ../../etc/group"
        reprozip trace bash -c "cat /etc/passwd;echo"
        reprozip trace --continue sh -c "cat /etc/group;/usr/bin/id"
        reprounzip graph graph.dot
        reprozip pack
        python tests/run.py
EOF
        ;;
    check_style)
        run_lines<<'EOF'
        flake8 --ignore=E126 reprozip/reprozip reprounzip/reprounzip
EOF
        ;;
    check_shared)
        run_lines<<'EOF'
        diff -q reprozip/reprozip/common.py reprounzip/reprounzip/common.py
        diff -q reprozip/reprozip/utils.py reprounzip/reprounzip/utils.py
EOF
        ;;
esac
