#!/bin/sh

set -e

cd $(dirname $0)
DIR=$(pwd)

cd $DIR/reprozip; python setup.py "$@"
cd $DIR/reprounzip; python setup.py "$@"
cd $DIR/reprounzip-docker; python setup.py "$@"
cd $DIR/reprounzip-vagrant; python setup.py "$@"
cd $DIR/reprounzip-vistrails; python setup.py "$@"
