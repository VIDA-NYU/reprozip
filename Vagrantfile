# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.provision "shell",
    inline: <<SCRIPT
aptitude update -y
aptitude install -y curl make gcc sqlite3 libsqlite3-dev python2.7-dev python-virtualenv libc6-dev
aptitude install -y xserver-xorg xserver-xorg-video-vesa xfwm4 x11-apps
SCRIPT

  config.vm.define "x86", autostart: false do |m|
    m.vm.box = "ubuntu/trusty32"
  end

  config.vm.define "x86_64" do |m|
    m.vm.box = "remram/debian-8-amd64"

    m.vm.provision "shell",
      inline: <<SCRIPT
aptitude install -y libc6-dev-i386 gcc-multilib docker.io
adduser vagrant docker
SCRIPT
  end

   # Default Port Forwarding
   default_ports = {
      80   => 8000,
      443  => 44300,
      3306 => 33060,
      5432 => 54320
   }

  # Use Default Port Forwarding Unless Overridden
  default_ports.each do |guest, host|
    config.vm.network "forwarded_port", guest: guest, host: host, auto_correct: true
  end
   	
  config.vm.define "travis", autostart: false do |m|
    m.vm.box = "hashicorp/precise64"
  end

  config.vm.provider "virtualbox" do |v|
    v.memory = 1024
  end
end
