travis-docker
=============

Running Docker in a Travis CI build

**.travis.yml** examples
------------------------

Run docker
```
install:
- curl -sLo - https://github.com/moul/travis-docker/raw/master/install.sh | sh -xe

script:
- PATH="${TRAVIS_BUILD_DIR}:${PATH}" docker run ubuntu /bin/echo Hello World
```
Run fig
```
install:
- curl -sLo - https://github.com/moul/travis-docker/raw/master/install.sh | sh -xe

script:
- PATH="${TRAVIS_BUILD_DIR}:${PATH}" fig run hello /bin/bash -c 'echo OK'
```

