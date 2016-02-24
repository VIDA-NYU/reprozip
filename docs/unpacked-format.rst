..  _unpacked-format:

Structure of Unpacked Experiments
*********************************

While *reprounzip* is designed to allow users to reproduce an experiment without having to master the tool used to run it (e.g.: `Vagrant <https://www.vagrantup.com/>`__ and `Docker <https://www.docker.com/>`__), in some situations it might be useful to go behind the scenes and interact with the unpacked experiments directly.

This page describes in more details how the unpackers operate.

..  note:: Future versions of unpackers might work in a different way. No attempt is made to make unpacked experiments compatible across different versions of *reprounzip*. Packages will always be compatible though.

..  _unpacked-common:

Common Files across Unpackers
=============================

The unpacked directory contains the original configuration file as ``config.yml``. In fact, the VisTrails integration relies on it.

A file named ``.reprounzip`` also marks the directory as an unpacked experiment. This is a Python pickle file containing a dictionary with various types of information:

* ``unpacker`` maps to the unpacker's name.
* ``input_files`` is used by the uploader/downloader machinery to keep the state of the input files inside the experiment, as they may be replaced by the user or overwritten by runs.
* Other information specific to the unpacker, as described next.

..  _unpacked-directory:

The `directory` Unpacker
========================

The experiment directory contains:

* The original configuration file ``config.yml``.
* The pickle file ``.reprounzip``.
* The tarball ``inputs.tar.gz``, which contains the original files that were identifies as input files. This tarball is used for file restoration using ``upload :<input-id>`` (see :ref:`unpacker-input-output`).
* A directory called ``root``, which contains all the packaged files in their original path, with symbolic links to absolute paths rewritten to prepend the path to ``root``.

::

    unpacked-directory/
        .reprounzip
        config.yml
        inputs.tar.gz
        root/
            ...

When running the ``run`` command, the unpacker sets ``LD_LIBRARY_PATH`` and ``PATH`` to point inside ``root``, and optionally ``DISPLAY`` and ``XAUTHORITY`` to the host's ones.

..  _unpacked-chroot:

The `chroot` Unpacker
=====================

The experiment directory contains:

* The original configuration file ``config.yml``.
* The pickle file ``.reprounzip``, which stores whether magic directories are mounted, as explained below.
* The tarball ``inputs.tar.gz``, which contains the original files that were identifies as input files. This tarball is used for file restoration using ``upload :<input-id>`` (see :ref:`unpacker-input-output`).
* A directory called ``root``, which contains all the packaged files in their original path, with no symbolic links rewritten and file ownership restored.

::

    unpacked-directory/
        .reprounzip
        config.yml
        inputs.tar.gz
        root/
            dev/
            dev/pts/
            proc/
            ...

If a file is listed in the configuration file but wasn't packed (i.e.: ``pack_files`` was set to ``false`` for a software package), such file is copied from the host; if this file does not exist on the host, a warning is shown when unpacking.

Unless ``--dont-bind-magic-dirs`` is specified when unpacking, the special directories ``/dev``, ``/dev/pts``, and ``/proc`` are mounted with ``mount -o bind`` from the host.
Also, if ``/bin/sh`` or ``/usr/bin/env`` weren't both packed, a static build of `busybox <https://busybox.net/>`__ is downloaded and put under ``/bin/busybox``, and the missing binaries are created as symbolic links pointing to busybox.

Should you require a shell inside the experiment environment, you can use::

    chroot root/ /bin/sh

..  _unpacked-vagrant:

The `vagrant` Unpacker
======================

The experiment directory contains:

* The original configuration file ``config.yml``.
* The pickle file ``.reprounzip``, which stores whether a chroot is used, as explained below.
* The tarball ``data.tgz``, which is part of the ``.rpz`` file and used to populate the virtual machine (VM) when it gets created.
* The setup script ``setup.sh``.
* The file ``rpz-files.list``, which contains the list of files to unpack. This list is passed to ``tar -T`` while unpacking.
* A ``Vagrantfile``, which is used to build the VM.

::

    unpacked-directory/
        .reprounzip
        config.yml
        data.tgz
        busybox
        Vagrantfile
        setup.sh
        rpz-files.list

Once ``vagrant up`` has been run by the ``setup/start`` command, a ``.vagrant`` subdirectory is created, and its content is managed by Vagrant (and appears to vary among different platforms).

Note that Vagrant drives VirtualBox or a similar virtualization software to run the VM. These will maintain state outside of the experiment directory. If you need to reconfigure or otherwise interact with the VM, you should do it from that virtualization software (e.g.: VirtualBox). The VM is named as the experiment directory with an additional suffix.

There are two modes for the virtual machine, controlled through command-line flags:

* The default mode, ``--use-chroot``, creates a chroot environment inside the VM at ``/experimentroot``. This allows ReproZip to unpack very different file system hierarchies without breaking the base system of the VM (in particular, ``ssh`` needs to keep working for the VM to be usable). In this mode, software packages that were not packed (i.e.: ``pack_files`` was set to ``false``) are installed in the VM and their required files are copied to the ``/experimentroot`` hierarchy. The software packages that were packed are simply copied over without any interaction with the VM's system.
* If ``--dont-use-chroot`` is used, no chroot environment is created. Files from software packages are never copied from the ``.rpz`` file; instead, they get installed from the package manager. Other files are simply unpacked in the VM system, possibly overwriting existing files. As long as *reprounzip-vagrant* manages to find a VM image with the same operating system as the original one, reproduction is expected to work reliably.

In the ``--use-chroot`` mode, a static build of `busybox <https://busybox.net/>`__ is downloaded and put under ``/experimentroot/busybox``, and if ``/bin/sh`` wasn't packed, it is created as a symbolic link pointing to busybox.

Uploading and downloading files from the environment is done via the shared directory ``/vagrant``, which is the experiment directory mounted in the VM by Vagrant.

Should you require a shell inside the experiment environment, you can use::

    vagrant ssh

Please be aware of whether ``--use-chroot`` is in use when accessing the experiment environment: in this case, the experiment's files are located under ``/experimentroot``.

..  _unpacked-docker:

The `docker` Unpacker
=====================

The experiment directory contains:

* The original configuration file ``config.yml``.
* The pickle file ``.reprounzip``, which stores the name of the images built by the unpacker, as explained below.
*  The tarball ``data.tgz``, which is part of the ``.rpz`` file and used to populate the Docker container.
* The file ``rpz-files.list``, which contains the list of files to unpack. This list is passed to ``tar -T`` while unpacking.
* A ``Dockerfile``, which is used to build the original image.

::

    unpacked-directory/
        .reprounzip
        config.yml
        data.tgz
        busybox
        rpzsudo
        Dockerfile
        rpz-files.list

Static builds of `busybox <https://busybox.net/>`__ and `rpzsudo <https://github.com/remram44/static-sudo/blob/master/rpzsudo.c>`__ are always downloaded and put into the Docker image as ``/busybox`` and ``/rpzsudo``, respectively.

Note that the ``docker`` command connects to a Docker daemon over a socket and that state will be changed there. The daemon might not be local; in particular, ``docker-machine`` might be used, which allows `reprounzip-docker` to be used on non-Linux machines, and the daemon might be in a virtual machine, on another host, or in the cloud. The `docker` unpacker will keep the environment variables set when calling Docker, notably ``DOCKER_HOST``, so these can be set accordingly before running the unpacker.

Images and containers built by the unpacker are given a random name with the prefixes ``reprounzip_image_`` and ``reprounzip_run_``, respectively; they are cleaned up when the ``destroy`` command is invoked. There are two images of which `reprounzip-docker` keeps track in the ``.reprounzip`` pickle file: the initial image, i.e., the one built by ``setup/build`` by calling ``docker build``, and the current image (initially the same as the initial image), which has been affected by a number of ``run`` and ``upload`` calls. Running the ``reset`` command returns to the initial image without having to rebuild. After each ``run`` invocation, the container is committed to a new current image so that state is kept.

Uploading files to the environment is done by running a simple Dockerfile that builds a new image. Downloading files is done via the ``docker cp`` command.
