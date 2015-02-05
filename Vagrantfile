# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.provision "shell",
    inline: <<SCRIPT
aptitude update -y
aptitude install -y make gcc sqlite3 libsqlite3-dev python2.7-dev python-virtualenv
SCRIPT

  config.vm.define "x86", autostart: false do |m|
    m.vm.box = "ubuntu/trusty32"
  end

  config.vm.define "x86_64" do |m|
    m.vm.box = "ubuntu/trusty64"
  end

  config.vm.provider "virtualbox" do |v|
    v.gui = true
    v.memory = 1024
  end
end
