..  _faq:

Frequently Asked Questions
**************************

.. _file_id:

Why `reprozip` does not identify my input/output file?
======================================================

ReproZip uses some heuristics to determine what is and what is not an input or output file. However, this is intended to be a starting point: you should check the configuration file (``input_files`` and ``output_files`` sections) and add/remove paths there; giving readable id names to input/output files, such as `database-log` or `lookup-table`, also helps.

..  _moving-outputs:

Why `reprounzip` cannot get my output files after reproducing an experiment?
============================================================================

This is probably the case where these output files do not have a fixed path name. It is common for experiments to dynamically choose where the outputs should be written, e.g.: by putting the date and time in the filename. However, ReproZip uses filenames in the ``output_files`` section of the configuration file to detect those when reproducing the experiment: if the name of the output file when reproducing is different from when it was originally packed, ReproZip cannot detect these as output files, and therefore, cannot get them through the ``download`` command.

The easiest way to solve this issue is to write a simple bash script that runs your experiment and either renames outputs or creates symbolic links to them with known filenames. You can then trace this script (instead of the actual entry-point of your experiment) and specify these fixed path names in the ``output_files`` section of the configuration file.

..  _systemd:

Why no files get packed when tracing a daemon?
==============================================

If you are starting the daemon via the `service` tool, it might be calling `init` over a client/server connection. In this situation, ReproZip will successfully pack the client, but anything the server (`init`) does will not be captured.

However, you can still trace the binary or a non-systemd `init` script directly. For example, instead of::

    reprozip trace service mysql start

you can trace either the `init` script::

    reprozip trace /etc/init.d/mysql start

or the binary::

    reprozip trace /usr/bin/mysqld
    
Note that, if you choose to trace the binary, you need to figure out the right command line options to use.
Also, make sure that systemd is not called, since ReproZip and systemd currently do not get along well.

Can ReproZip pack a client-server scenario?
===========================================

Yes! However, note that only tracing the client will not capture the full story: reproducibility is better achieved (and guaranteed) if the server is traced as well.
Having said that, currently, ReproZip can only trace local servers: if in your experiment the server is remote (i.e., running in another machine), ReproZip cannot capture it. In this case, you can trace the client, and the experiment can only be reproduced if the remote server is still running at the moment of the reproduction.

The easiest way to pack a local client-server experiment is to write a script that starts the server, runs your client(s), and then shuts down the server; ReproZip can then trace this script. See :ref:`Further Considerations When Packing <packing-further>` for more information.

Can ReproZip pack a database?
=============================

ReproZip can trace a database server; however, because of the format it uses to store data (and also because different databases work differently), it might be hard for you to control exactly what data will be packed. You probably want to pack all the data from the databases/tables that your experiment uses, and not just the pages that were touched while tracing the execution. This can be done by inspecting the configuration file and adding the relevant patterns that cover the data, e.g.: for MySQL::

    additional_patterns:
      - /var/lib/mysql/**
      
Also note that ReproZip does not currently save the state of the files. Therefore, if your experiment modifies a database, ReproZip will pack the already modified data (not the one before tracing the experiment execution).

Can ReproZip pack interactive tools?
====================================

Yes! The `reprounzip` component should have no problems with experiments that interact with the user through the terminal. If your experiment runs until it receives a Ctrl+C signal, that is fine as well: ReproZip will not interfere unless you press Ctrl+C twice, stopping the experiment.

GUI tools are also supported, see :ref:`next section <gui-tools>`.

..  _gui-tools:

Can ReproZip pack graphical (GUI) tools?
========================================

On Linux, graphical display is handled by the X server, to which applications can connect as clients to display their windows and components, and get user input.

Most unpackers now support forwarding the X connection from the experiment to the X server running on your machine. Note that you will need a running X server for this to work, such as `Xming <http://sourceforge.net/projects/xming/>`_ for Windows or `XQuartz <http://xquartz.macosforge.org/>`_ for Mac OS. If you are running Linux, chances are that an X server is already configured and running.

Note that X support is not enabled by default; use the ``--enable-x11`` flag to your unpacker of choice's ``run`` command to use it.

Can I access the generated system or virtual machine directly?
==============================================================

You can connect to the Vagrant virtual machine by running "vagrant ssh", or connecting via SSH to the destination listed by "vagrant ssh-config" (usually localhost:2222). These commands should be run from inside the directory created by unpacking.

You can inspect the containers created by `docker`, or start one based on the image created by reprounzip. They are named with the ``reprounzip_`` prefix.

With `chroot` and `directory`, the filesystem is in the ``root`` subdirectory below the unpacked path.

..  warning::

    Only the files necessary for running the experiment are required to work correctly. This means that you could very well have only parts of a software distribution, if the pack author didn't edit the configuration to add them in their entirety. For example, you could have the parts of Python that the experiment ran, but nothing else, and in particular not the ones needed to run Python interactively or install new libraries.

    The utilities from the base system might also not work correctly (if they are not part of the experiment) because `reprounzip` will overwrite their libraries with the experiment's. In the worse case, the dynamic linker or the shell might not be usable. Some unpackers install ``/bin/busybox`` which you might find helpful.

My experiment fails to run with ``Error: Can't open display: :0``
=================================================================

`reprounzip` now supports GUI tools, but it is not enabled by default. Add the ``--enable-x11`` flag to the ``run`` command to use it. See :ref:`gui-tools`.

What if my experiment runs on a distributed environment?
========================================================

ReproZip cannot trace across multiple machines. You could trace each component separately, but ReproZip has no support yet to setup these multiple machines in the right way from the multiple ``.rpz`` files. In particular, you will probably need to set up the same network for the components to talk to each other.

What if I need to pack multiple command lines?
==============================================

The easiest way, in this case, is to write a script that runs all the desired command lines, and then to trace the execution of this script with `reprozip`.

..  _pycrypto_windows:

Why `reprounzip-vagrant` installation fails with error ``Unable to find vcvarsall.bat`` on Windows?
===================================================================================================

Python is trying to build `PyCrypto <https://www.dlitz.net/software/pycrypto/>`_, one of the dependencies of `reprounzip-vagrant`, but there is no C compiler available. You can either build PyCrypto from source, or follow the instructions on `this website <http://stackoverflow.com/questions/11405549/how-do-i-install-pycrypto-on-windows>`_ to get the non-official binaries.

..  _compiler_mac:

Why `reprounzip-vagrant` installation fails with error ``unknown argument: '-mno-fused-madd'`` on Mac OS X?
===========================================================================================================

This is an issue with the Apple LLVM compiler, which treats unrecognized command-line options as errors. As a workaround, before installing `reprounzip-vagrant`, run the following::

    $ sudo -s
    $ export CFLAGS="-Wno-error=unused-command-line-argument-hard-error-in-future"

Then re-install `reprounzip-vagrant`::

    $ pip install -I reprounzip-vagrant

Or use the following command in case you want all the available plugins::

    $ pip install -I reprounzip[all]

..  _scp-py3:

Why I am having issues with `reprounzip-vagrant` on Python 3?
=============================================================

The `reprounzip-vagrant` plugin is compatible with Python 3; however, the **scp.py** library used to transfer files to and from the virtual machine has a number of issues. Until the maintainer accepts our patch, you can install our fixed version from GitHub using::

    pip install 'git+https://github.com/remram44/scp.py.git#egg=scp'

.. _directory_error:

Why does `reprounzip directory` fail with ``IOError``?
======================================================

The `directory` unpacker does not provide any isolation from the filesystem, so if the experiment being reproduced use absolute paths, these will point outside the experiment directory, and files may not be found. Make sure that the experiment does not use any absolute paths: if only relative paths are used internally and in the command line, ``reprounzip directory`` should work.

..  _distribnotfound:

Why does `reprounzip` fail with ``DistributionNotFound`` errors?
================================================================

You probably have some plugins left over from a previous installation. Be sure to upgrade or remove outdated plugins when you upgrade reprounzip.

The following command might help::

    pip install -U reprounzip[all]

Why does `reprounzip` show ``running in chroot, ignoring request``?
===================================================================

This message comes from the systemd client, which will probably not work with ReproZip. In this case, the experiment should be re-packed without using systemd (see :ref:`this question <systemd>` for more information).

Why does ``reprounzip vagrant setup`` fail to resolve a host address?
=====================================================================

When running ``reprounzip vagrant setup``, if you get an error similar to this::

    ==> default: failed: Temporary failure in name resolution.
    ==> default: wget: unable to resolve host address ...

there is probably a firewall blocking the Vagrant VM to have Internet connection; the VM needs Internet connection to download required software for setting up the experiment for you. Please make sure that your anti-virus/firewall is not causing this issue.

Why does ``reprounzip run`` fail with ``no such file or directory`` or similar?
===============================================================================

This cryptic error message can come from different sources, for instance missing a specific version of a library or dynamic linker.

While ReproZip usually packs every file that is needed for the experiment to run, but you can optionally request `reprounzip` to install packages from the distribution's package manager instead. The pack author can also choose not to include some packages, meaning that `reprounzip` will have to install the distribution's, which is not guaranteed to be compatible.

Using a base system that's closer to the one the experiment was packed on can also help; see the ``--base-image`` option for the Vagrant and Docker unpackers.
