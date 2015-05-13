#!/bin/sh

set -xe

# version numbers
COMPOSE_VERSION=1.2.0
BRANCH=${BRANCH:-master}


# Disable post-install autorun
echo exit 101 | sudo tee /usr/sbin/policy-rc.d
sudo chmod +x /usr/sbin/policy-rc.d


# Install dependencies
sudo apt-get update
sudo apt-get install -y slirp lxc aufs-tools cgroup-lite


# Install docker
curl -s https://get.docker.com/ | sh
sudo usermod -aG docker $USER
sudo chown -R travis /etc/docker


# Install fig
sudo curl -L https://github.com/docker/fig/releases/download/1.0.1/fig-`uname -s`-`uname -m` -o /usr/local/bin/fig
sudo chmod +x /usr/local/bin/fig


# Install docker-compose
sudo curl -L https://github.com/docker/compose/releases/download/$COMPOSE_VERSION/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose


# Download binary
curl -sLo linux https://github.com/jpetazzo/sekexe/raw/master/uml
curl -sLo linux-init https://github.com/moul/travis-docker/raw/${BRANCH}/linux-init
curl -sLo run https://github.com/moul/travis-docker/raw/${BRANCH}/run
chmod +x linux linux-init run
