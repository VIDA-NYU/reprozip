travis-docker [![Build Status](https://travis-ci.org/moul/travis-docker.svg?branch=master)](https://travis-ci.org/moul/travis-docker)
=============

Running Docker in a Travis CI build

Inspired by https://github.com/lukecyca/travis-docker-example

**.travis.yml** examples
------------------------

Run any command inside the pseudo-linux

    install:
    - curl -sLo - https://github.com/moul/travis-docker/raw/master/install.sh | sh -xe
    script:
    - ./run docker run busybox ls -la
    - ./run docker run busybox ls -la /non-existing-dir

Chain commands

    ...
    script:
    - ./run /bin/bash -c 'docker-compose up -d blog && docker ps && date'

License
=======

MIT
