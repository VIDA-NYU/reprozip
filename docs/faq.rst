..  _faq:

Frequently Asked Questions
**************************

..  _file_id:

Why doesn't `reprozip` identify my input/output file?
=====================================================

ReproZip uses some heuristics to identify an input or output file. However, this is only intended to be a starting point: you should check the configuration file and edit the ``inputs_outputs`` section if necessary; giving readable names to input/output files also helps during reproduction. Please refer to :ref:`packing-config` for more information.

..  _moving-outputs:

Why can't `reprounzip` get my output files after reproducing an experiment?
===========================================================================

This is probably the case where these output files do not have a fixed path name. It is common for experiments to dynamically choose where the outputs should be written, e.g.: by putting the date and time in the filename. However, ReproZip uses filenames in the ``output_files`` section of the configuration file to detect those when reproducing the experiment: if the name of the output file when reproducing is different from when it was originally packed, ReproZip cannot detect these as output files, and therefore, cannot get them through the ``download`` command.

The easiest way to solve this issue is to write a simple bash script that runs your experiment and either renames outputs or creates symbolic links to them with known filenames. You can then trace this script (instead of the actual entry-point of your experiment) and specify these fixed path names in the ``output_files`` section of the configuration file.

..  _systemd:

Why aren't any files packed when tracing a daemon?
==================================================

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

GUI tools are also supported; see :ref:`gui-tools` for more information.

..  _gui-tools:

Can ReproZip pack graphical tools?
==================================

Yes!
On Linux, graphical display is handled by the X server, to which applications can connect as clients to display their windows and components, and to get user input.
Most unpackers now support forwarding the X connection from the experiment to the X server running on the unpacking machine. Note that you will need a running X server to make this work, such as `Xming <http://sourceforge.net/projects/xming/>`__ for Windows or `XQuartz <http://xquartz.macosforge.org/>`__ for Mac OS X. If you are running Linux, chances are that an X server is already configured and running.

X support is **not** enabled by default; to enable it, use the flag ``--enable-x11`` in the ``run`` command of your preferred unpacker.

How can I access the generated system or virtual machine directly?
==================================================================

If you are running ``reprounzip vagrant``, you can connect to the Vagrant virtual machine by running ``vagrant ssh`` or connecting via SSH to the destination listed by ``vagrant ssh-config`` (often ``localhost:2222``). These commands should be run from inside the directory created by the unpacker.

If you are running ``reprounzip docker``, you can inspect the Docker container directly by using ``docker``, or start a new one based on the image created by `reprounzip`; all images  generated by ReproZip are named with the ``reprounzip_`` prefix. For more information on how to inspect and create Docker containers, please refer to the `Docker documentation <https://docs.docker.com/>`__.

For ``reprounzip chroot`` and ``reprounzip directory``, the filesystem is in the ``root`` subdirectory under the experiment path.

..  warning::

    Note that, in the generated system, only the files needed for running the unpacked experiment are guaranteed to work correctly. This means that you may have only parts of a software distribution (required to run the experiment), but not the software in its entirety (unless the complete software was included in the configuration file while packing). For example, you may only have a few Python files that the experiment needs, but not the ones required to run Python interactively or install new libraries. Therefore, do not expect that all the software components will run smoothly when acessing the system.

    The utilities from the base system might also not work correctly (if they are not part of the experiment) because `reprounzip` overwrites the libraries with the ones from the original environment. In the worst-case scenario, the dynamic linker or the shell may not be usable. Note that some unpackers install ``/bin/busybox``, which you may find helpful.

What if my experiment runs on a distributed environment?
========================================================

ReproZip cannot trace across multiple machines. You could trace each component separately, but ReproZip has no support yet to setup these multiple machines in the right way from the multiple ``.rpz`` files. In particular, you will probably need to set up the same network for the components to talk to each other.

..  _pycrypto_windows:

Why does `reprounzip-vagrant` installation fail with error ``Unable to find vcvarsall.bat`` on Windows?
=======================================================================================================

Python is trying to build `PyCrypto <https://www.dlitz.net/software/pycrypto/>`__, one of the dependencies of `reprounzip-vagrant`, but there is no C compiler available. You can either build PyCrypto from source, or follow the instructions on `this website <http://stackoverflow.com/questions/11405549/how-do-i-install-pycrypto-on-windows>`__ to get the non-official binaries.

..  _compiler_mac:

Why does `reprounzip-vagrant` installation fail with error ``unknown argument: '-mno-fused-madd'`` on Mac OS X?
===============================================================================================================

This is an issue with the Apple LLVM compiler, which treats unrecognized command-line options as errors. As a workaround, before installing `reprounzip-vagrant`, run the following::

    $ sudo -s
    $ export CFLAGS="-Wno-error=unused-command-line-argument-hard-error-in-future"

Then re-install `reprounzip-vagrant`::

    $ pip install -I reprounzip-vagrant

Or use the following command in case you want all the available plugins::

    $ pip install -I reprounzip[all]

Why are there warnings from requests/urllib3?
=============================================

You may be seeing warnings like this::

    /usr/local/lib/python2.7/dist-packages/requests/packages/urllib3/util/ssl_.py:79:
    InsecurePlatformWarning: A true SSLContext object is not available. This
    prevents urllib3 from configuring SSL appropriately and may cause certain SSL
    connections to fail. For more information, see
    https://urllib3.readthedocs.org/en/latest/security.html#insecureplatformwarning.

Most Python versions are insecure, because they do not validate SSL certificates. Python 2.7.9 and later shouldn't be affected, but if you see ``InsecurePlatformWarning``, you can run ``pip install requests[security]``, which should bring in the missing components.

Why does the experiment fail with ``Error: Can't open display: :0``?
====================================================================

The experiment probably involves running a GUI tool. The `reprounzip` component supports GUI tools, but it is not enabled by default; add the flag ``--enable-x11`` to the ``run`` command to enable it. See :ref:`gui-tools` for more information.

..  _directory_error:

Why does `reprounzip directory` fail with ``IOError``?
======================================================

The `directory` unpacker does not provide any isolation from the filesystem: if the experiment being reproduced use absolute paths, these will point outside the experiment directory, and files may not be found. Make sure that the experiment does not use any absolute paths: if only relative paths are used internally and in the command line, ``reprounzip directory`` should work.

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

..  _nosuchfile:

Why does ``reprounzip run`` fail with ``no such file or directory`` or similar?
===============================================================================

This error message may have different reasons, but it often means that a specific version of a library or a dynamic linker is missing.

If you are requesting `reprounzip` to install software using the package manager (by running ``reprounzip installpkgs``), it is possible that the software packages from the package manager are not compatible with the ones required by the experiment. You may want to try using the packed files directly to ensure compatibility. Also, note that, while packing, the user can choose not to include some packages, meaning that `reprounzip` will have to install the one from the package manager, which, again, is not guaranteed to be compatible. In this case, try contacting the author of the ReproZip package.

When using ``reprounzip vagrant`` and ``reprounzip docker``, ReproZip tries to detect the closest base system for unpacking the experiment. You may also want to try a different base system that you think it is closer to the original one by using the option ``--base-image`` when running these unpackers.
