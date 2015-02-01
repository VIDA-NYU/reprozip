#!/bin/sh

set -e
set -u

cd "$(dirname $0)"

PROGRAMS="./reprounzip ./reprounzip-docker ./reprounzip-vagrant ./reprounzip-vistrails"
if [ "$(uname -s)" = Linux ]; then
    PROGRAMS="./reprozip $PROGRAMS"
fi

arg="${1:-}"
if [ "$arg" = install ]; then
    pip install -U $PROGRAMS
elif [ "$arg" = develop ]; then
    # -e doesn't work with local paths before 6.0
    pip install -U setuptools pip
    for prog in $PROGRAMS; do
        pip install -U -e $prog
    done
else
    echo "Usage: $(basename "$0") <install|develop>" >&2
    exit 1
fi
