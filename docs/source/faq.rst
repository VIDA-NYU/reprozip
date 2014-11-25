..  _faq:

Frequently Asked Questions
**************************
    
Why `reprozip` does not identify my input/output file?
======================================================

ReproZip uses some heuristics to determine what is and what is not an input or output file. However, this is intended to be a starting point: you should check the configuration file (``input_files`` and ``output_files`` sections) and add/remove paths there; giving readable id names to input/output files, such as `database-log` or `lookup-table` also helps.

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

Note, however, that running GUI tools (connecting to an X server) is yet not supported by ReproZip.

What if my experiment runs on a distributed environment?
========================================================

ReproZip cannot trace across multiple machines. You could trace each component separately, but ReproZip has no support yet to setup these multiple machines in the right way from the multiple ``.rpz`` files. In particular, you will probably need to set up the same network for the components to talk to each other.

What if I need to pack multiple command lines?
==============================================

The easiest way, in this case, is to write a script that runs all the desired command lines, and then to trace the execution of this script with `reprozip`.

..  _scp-py3:

Why I am having issues with `reprounzip-vagrant` on Python 3?
=============================================================

The `reprounzip-vagrant` plugin is compatible with Python 3; however, the **scp.py** library used to transfer files to and from the virtual machine has a number of issues. Until the maintainer accepts our patch, you can install our fixed version from GitHub using::

    pip install 'git+https://github.com/remram44/scp.py.git#egg=scp'
    
    ..  _distribnotfound:

Why `reprounzip` shows DistributionNotFound errors?
===================================================

You probably have some plugins left over from a previous installation. Be sure to upgrade or remove outdated plugins when you upgrade reprounzip.

The following command might help::

    pip install -U reprounzip[all]
    
Why `reprounzip` shows ``running in chroot, ignoring request``?
===============================================================

This message comes from the systemd client, which will probably not work with ReproZip. In this case, the experiment should be re-packed without using systemd (see :ref:`this question <systemd>` for more information).
