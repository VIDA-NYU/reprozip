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

TODO

..  _unpacked-vagrant:

`vagrant` unpacker
==================

TODO

..  _unpacked-docker:

`docker` unpacker
=================

TODO
