# travis-docker [![Build Status](https://img.shields.io/travis/moul/travis-docker.svg)](https://travis-ci.org/moul/travis-docker)

Running Docker in a Travis CI build.

`./run` script will run commands in a user-land linux with `docker` and `docker-compose` and pass back the exit code

Inspired by [lukecyca/travis-docker-example](https://github.com/lukecyca/travis-docker-example)


## *.travis.yml* examples

```yaml
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

## Limitations

1. `/var/lib/docker` is not persistent across `./run` calls, but you can chain command calls in a unique `./run` or use `docker-compose`


## Projects using [travis-docker](https://github.com/moul/travis-docker)

- https://github.com/CloudSlang/cloud-slang-content
- https://github.com/ir4y/fabric-scripts
- https://github.com/moul/docker-icecast
- https://github.com/pathwar/core
- https://github.com/pathwar/level-helloworld
- https://github.com/scaleway/kernel-tools
- https://github.com/stevenalexander/docker-nginx-dropwizard
- https://github.com/William-Yeh/ansible-nginx
- https://github.com/William-Yeh/ansible-nodejs
- https://github.com/William-Yeh/docker-ansible
- https://github.com/William-Yeh/docker-dash
- https://github.com/William-Yeh/docker-mini
- https://github.com/William-Yeh/docker-wrk

## License

MIT
