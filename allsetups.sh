#!/bin/sh

set -e
set -u

cd "$(dirname $0)"

PROGRAMS="reprounzip reprounzip-docker reprounzip-vagrant reprounzip-singularity reprounzip-vistrails reprounzip-qt reprozip-jupyter"
if [ "$(uname -s)" = Linux ]; then
    PROGRAMS="reprozip $PROGRAMS"
fi

arg="${1:-}"
if [ "$arg" = install ]; then
    CMD=""
    for prog in $PROGRAMS; do
        CMD="$CMD ./$prog"
    done
    pip install -U $CMD
elif [ "$arg" = develop ]; then
    # -e doesn't work with local paths before 6.0
    pip install -U setuptools pip
    CMD=""
    for prog in $PROGRAMS; do
        CMD="$CMD -e ./$prog"
    done
    pip install -U $CMD
elif [ "$arg" = uninstall ]; then
    for prog in $PROGRAMS; do
        pip uninstall -y $prog || true
    done
else
    echo "Usage: $(basename "$0") <install|develop|uninstall>" >&2
    exit 1
fi
