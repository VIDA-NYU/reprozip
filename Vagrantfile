# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "hashicorp/precise32"

  config.vm.provision "shell",
    inline: <<SCRIPT
aptitude update
aptitude install -y make gcc libsqlite3-dev python2.7-dev python-virtualenv
SCRIPT
end
