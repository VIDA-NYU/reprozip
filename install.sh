#!/bin/sh

sudo sh -c "wget -qO- https://get.docker.io/gpg | apt-key add -"
sudo sh -c "echo deb http://get.docker.io/ubuntu docker main > /etc/apt/sources.list.d/docker.list"
sudo apt-get update
sudo mkdir -p /var/lib/docker
echo exit 101 | sudo tee /usr/sbin/policy-rc.d
sudo chmod +x /usr/sbin/policy-rc.d
sudo apt-get install -y slirp lxc lxc-docker aufs-tools cgroup-lite

curl -sLo linux https://github.com/jpetazzo/sekexe/raw/master/uml
curl -sLo linux-init https://github.com/moul/travis-docker/raw/master/linux-init
curl -sLo docker https://github.com/moul/travis-docker/raw/master/docker
chmod +x linux linux-init docker
