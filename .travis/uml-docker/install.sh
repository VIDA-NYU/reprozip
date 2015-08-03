#!/bin/sh


# version numbers
COMPOSE_VERSION=1.2.0


cd "$(dirname "$0")"


# Disable post-install autorun
echo exit 101 | sudo tee /usr/sbin/policy-rc.d
sudo chmod +x /usr/sbin/policy-rc.d


# Install dependencies
sudo apt-get update
sudo apt-get install -y slirp lxc aufs-tools cgroup-lite


# Avoid running installed daemons
echo exit 101 | sudo tee /usr/sbin/policy-rc.d
sudo chmod +x /usr/sbin/policy-rc.d


# Install docker
#curl -s https://get.docker.com/ | sh
DOCKER_VERSION=${DOCKER_VERSION:-1.7.1}
if [ "x$DOCKER_VERSION" = "xget.docker.com" ]; then
    curl -s https://get.docker.com/ | sh -xe
else
    sudo mkdir -p /var/lib/docker
    wget https://get.docker.io/ubuntu/pool/main/l/lxc-docker-${DOCKER_VERSION}/lxc-docker-${DOCKER_VERSION}_${DOCKER_VERSION}_amd64.deb && \
        sudo dpkg -i lxc-docker-${DOCKER_VERSION}_${DOCKER_VERSION}_amd64.deb && \
        rm -f lxc-docker-${DOCKER_VERSION}_${DOCKER_VERSION}_amd64.deb
fi
sudo mkdir -p /etc/docker
sudo usermod -aG docker $USER
sudo chown -R $USER /etc/docker


# Install fig
if [ "x$UML_FIG" != x0 ]; then
    sudo curl -L https://github.com/docker/fig/releases/download/1.0.1/fig-`uname -s`-`uname -m` -o /usr/local/bin/fig
    sudo chmod +x /usr/local/bin/fig
fi


# Install docker-compose
if [ "x$UML_DOCKERCOMPOSE" != x0 ] ; then
    sudo curl -L https://github.com/docker/compose/releases/download/$COMPOSE_VERSION/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
fi


# Download binary
curl -sLo linux https://github.com/jpetazzo/sekexe/raw/master/uml
chmod +x linux
