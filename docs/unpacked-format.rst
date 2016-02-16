..  _unpacked-format:

Internal format of unpacked experiments
***************************************

While *reprounzip* is designed to allow users to reproduce an experiment without having to master the tool used to run it (e.g. vagrant, docker): the unpacker drives it automatically. However, in some situations it might be useful to go behind the scenes and interact with the unpacked experiment directly. This page describes how the various unpackers operate.

Note that future versions of unpackers might work in a different way. No attempt is made to make unpacked experiments compatible across different versions of *reprounzip*.

..  _unpacked-directory:

`directory` unpacker
====================

The experiment directory contains the original configuration file ``config.yml``, the pickle file ``.reprounzip``, and a tarball ``inputs.tar.gz`` which contains the original files that are input files (for restauration using ``upload :<input-id>``).

A directory called ``root`` contains all the packaged files in their original path, with symbolic links to absolute paths rewritten to prepend the path to ``root``.

::

    unpacked-directory/
        .reprounzip
        config.yml
        inputs.tar.gz
        root/
            ...

When running `run`, the unpacker sets ``LD_LIBRARY_PATH`` and ``PATH`` to point inside ``root``, and optionally ``DISPLAY`` and ``XAUTHORITY`` to the host's.

..  _unpacked-chroot:

`chroot` unpacker
=================

The experiment directory contains the original configuration file ``config.yml``, the pickle file ``.reprounzip`` (storing whether magic directories are mounted, see below), and a tarball ``inputs.tar.gz`` which contains the original files that are input files (for restauration using ``upload :<input-id>``).

A directory called ``root`` contains all the packaged files in their original path. Symbolic links are not rewritten. If a file is listed in the pack's configuration but wasn't packed (``pack_files`` was set to false for a software package), it is copied from the host (if it doesn't exist on the host, a warning is shown when unpacking). File ownership is also restored.

Unless ``--dont-bind-magic-dirs`` is specified when unpacking, the special directories ``/dev``, ``/dev/pts``, and ``/proc`` are mounted with ``mount -o bind`` from the host.

If ``/bin/sh`` or ``/usr/bin/env`` weren't both packed, a static build of busybox is downloaded and put in ``/bin/busybox``, and the missing binaries are created as symbolic links pointing to busybox.

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

Should you require a shell inside the experiment environment, you can use::

    chroot root/ /bin/sh

..  _unpacked-vagrant:

`vagrant` unpacker
==================

The experiment directory contains the original configuration file ``config.yml``, the pickle file ``.reprounzip`` (containing whether a chroot is used, see below), the DATA part of the ``.rpz`` file as ``data.tgz`` used to populate the VM when it gets created, a setup script ``setup.sh``, a file ``rpz-files.list`` with the list of files to unpack that is passed to ``tar -T``, and a ``Vagrantfile``. Once ``vagrant up`` has been run by the ``setup/start`` step, a ``.vagrant`` subdirectory exists, whose content is managed by Vagrant (and appears to vary between platforms).

Note that Vagrant drives VirtualBox or a similar virtualization software to run the VM. These will maintain state outside of the experiment folder, and should you need to reconfigure or otherwise interact with the VM, you should do it from that software's UI. The VM is usually named like the experiment directory with a suffix.

There are two modes for the virtual machine:

* The default, ``--use-chroot``, creates a chroot environment inside the virtual machine at ``/experimentroot``. This allows us to unpack very different file system hierarchies without breaking the base system of the VM (in particular, SSH needs to keep working for the VM to be usable). In this mode, the packages that were not packed (``pack_files`` set to false) are installed in the VM and their required files are copied to the ``/experimentroot`` hierarchy. The software packages that were packed are simply copied over without any interaction with the VM's system.
* If ``--dont-use-chroot`` is passed, no chroot environment is created. The files from software packages are never copied from the ``.rpz``, they get installed from the package manager. The other files are simply unpacked in the VM system, possibly overwriting files. If the systems are different enough, things will probably not work, but as long as reprounzip-vagrant manages to find a VM image with the same operating system, we can expect reproduction to be work reliably.

In ``--use-chroot`` mode, a static build of busybox is downloaded and put in ``/experimentroot/busybox``, and if ``/bin/sh`` wasn't packed, it is created as a symbolic link pointing to busybox.

Uploading and downloading files from the environment is done via the shared directory ``/vagrant`` which is the experiment directory mounted in the VM by Vagrant.

Should you require a shell inside the experiment environment, you can use::

    vagrant ssh

Please be aware of whether ``--use-chroot`` is in use (then ``/experimentroot`` exists and this is where the experiment's files are).

..  _unpacked-docker:

`docker` unpacker
=================

TODO
