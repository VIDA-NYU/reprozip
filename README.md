# travis-docker
[![Build Status](https://img.shields.io/travis/moul/travis-docker.svg)](https://travis-ci.org/moul/travis-docker)

Running Docker in a Travis CI build.

`./run` script will run commands in a user-land linux with `docker` and
`docker-compose` and pass back the exit code.


## *.travis.yml* example

```yaml
env:
  global:
    - BRANCH=stable
    - QUIET=1

sudo: true

install:
  - curl -sLo - http://j.mp/install-travis-docker | sh -xe

script:
  - ./run docker run busybox ls -la
  - ./run docker run busybox ls -la /non-existing-dir
  - ./run 'docker-compose up -d blog && docker ps && date'
  - ./run 'apt-get install git && git clone && docker -f ...'
  - ./run 'docker build -t test . && docker run test'
```

You can find more examples on [travis-docker-example](https://github.com/moul/travis-docker-example).


## Environment variables

* `DOCKER_STORAGE_DRIVER=aufs`, default is `devicemapper`, available values are
  `aufs`, `btrfs`, `devicemapper`, `vfs`, `overlay`
* `UML_DOCKERCOMPOSE=0`, do not install `docker-compose`
* `UML_FIG=0`, do not install `fig`
* `QUIET=1`, be less verbose


---

## Changelog

### v1.0.0 (2015-06-02) (BRANCH=v1.0.0 or BRANCH=stable)

First stable version

usage: .travis.yml

```yaml
env:
  global:
    - BRANCH=v1.0.0
    - QUIET=1

sudo: true

install:
  - curl -sLo - http://j.mp/install-travis-docker | sh -xe

script:
  - ./run 'docker build -t test . && docker run test'
  - ./run 'docker-compose up -d blog && docker ps'
```

* First "stable" version
* /var/lib/docker is mounted as tmpfs (limited to 2Gib)
* No persistency between `./run` calls
* Optional packages `fig` and `docker-compose` are installed by default and
  can be skiped with `UML_FIG=0` `UML_DOCKERCOMPOSE=0`
* Verbose mode is enabled by default and can be disabled with `QUIET=1`
* Default storage driver is `aufs` and can be changed using
  `DOCKER_STORAGE_DRIVER={devicemapper,aufs,btrfs,vfs,overlay}`


### v0.0.0 (2015-01-18)

Proof of concept


---

## Projects using [travis-docker](https://github.com/moul/travis-docker)

- https://github.com/andrewsomething/fabric-package-management
- https://github.com/CloudSlang/cloud-slang-content
- https://github.com/eliotjordan/rails-docker-test
- https://github.com/HanXHX/ansible-debian-dotdeb
- https://github.com/ir4y/fabric-scripts
- https://github.com/moul/docker-icecast
- https://github.com/moul/travis-docker-example
- https://github.com/pathwar/core
- https://github.com/pathwar/level-helloworld
- https://github.com/rporrini/abstat-akp-inference
- https://github.com/scaleway/kernel-tools
- https://github.com/stevenalexander/docker-nginx-dropwizard
- https://github.com/theodi/british_values
- https://github.com/Webtrends/wookie
- https://github.com/William-Yeh/ansible-nginx
- https://github.com/William-Yeh/ansible-nodejs
- https://github.com/William-Yeh/docker-ansible
- https://github.com/William-Yeh/docker-dash
- https://github.com/William-Yeh/docker-mini
- https://github.com/William-Yeh/docker-wrk

## License

MIT
