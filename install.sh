#!/bin/sh

set -xe

# Disable post-install autorun
echo exit 101 | sudo tee /usr/sbin/policy-rc.d
sudo chmod +x /usr/sbin/policy-rc.d

# Install dependencies
sudo apt-get update
sudo apt-get install -y slirp lxc aufs-tools cgroup-lite

# Install docker 1.4.1 (see https://github.com/moul/travis-docker/issues/4)
# sudo sh -c "wget -qO- https://get.docker.io/gpg | apt-key add -"
# sudo sh -c "echo deb http://get.docker.io/ubuntu docker main > /etc/apt/sources.list.d/docker.list"
sudo mkdir -p /var/lib/docker
wget https://get.docker.io/ubuntu/pool/main/l/lxc-docker-1.4.1/lxc-docker-1.4.1_1.4.1_amd64.deb && \
  sudo dpkg -i lxc-docker-1.4.1_1.4.1_amd64.deb && \
  rm -f lxc-docker-1.4.1_1.4.1_amd64.deb

# Install fig
sudo curl -L https://github.com/docker/fig/releases/download/1.0.1/fig-`uname -s`-`uname -m` -o /usr/local/bin/fig
sudo chmod +x /usr/local/bin/fig

# Download binary
curl -sLo linux https://github.com/jpetazzo/sekexe/raw/master/uml
curl -sLo linux-init https://github.com/moul/travis-docker/raw/master/linux-init
curl -sLo run https://github.com/moul/travis-docker/raw/master/run
chmod +x linux linux-init run
