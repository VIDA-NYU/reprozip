travis-docker [![Build Status](https://travis-ci.org/moul/travis-docker.svg?branch=master)](https://travis-ci.org/moul/travis-docker)
=============

Running Docker in a Travis CI build

**.travis.yml** examples
------------------------

Run any command inside the pseudo-linux

    install:
    - curl -sLo - https://github.com/moul/travis-docker/raw/master/install.sh | sh -xe
    script:
    - ./run /bin/bash -c 'fig up -d blog; docker ps; date'

---

Run docker

    install:
    - curl -sLo - https://github.com/moul/travis-docker/raw/master/install.sh | sh -xe
    script:
    - PATH="${TRAVIS_BUILD_DIR}:${PATH}" docker run ubuntu /bin/echo Hello World

---

Run fig

    install:
    - curl -sLo - https://github.com/moul/travis-docker/raw/master/install.sh | sh -xe
    script:
    - PATH="${TRAVIS_BUILD_DIR}:${PATH}" fig run hello /bin/bash -c 'echo OK'

License
=======

MIT
