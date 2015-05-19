# travis-docker [![Build Status](https://travis-ci.org/moul/travis-docker.svg?branch=master)](https://travis-ci.org/moul/travis-docker)

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


## License

MIT
