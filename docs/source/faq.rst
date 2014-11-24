..  _faq:

Frequently Asked Questions
**************************

..  _distribnotfound:

reprounzip shows errors with DistributionNotFound
=================================================

You probably have some plugins left over from a previous installation. Be sure to upgrade or remove outdated plugins when you upgrade reprounzip.

The following command might help::

    pip install -U reprounzip[all]

..  _moving-outputs:

My experiment's output files have no fixed path
===============================================

It is common for experiments to dynamically choose where the outputs should be written, for example by putting the date and time in the filename. However, ReproZip cannot understand these non-reproducible names; you need to put a single filename in the ``input_files`` sectin of your configuration file.

The easiest way to solve that is to write a simple bash script that runs your experiment, then renames the output to a known filename, or creates a symbolic link to it. You can then trace this script instead of the actual entry-point of your experiment, and specify that link as the path in the ``input_files`` dictionary.

..  _systemd:

I'm tracing a daemon, but no files get packed
=============================================

If you are starting the daemon via the `service` tool, it might be calling init over a client/server connection. In this kind of situation, ReproZip will successfully pack the client, but anything the server (init) does won't be captured.

However, you can still trace the binary or a non-systemd initscript directly. For example, instead of::

    reprozip trace service mysql start

Use either the initscript (make sure it doesn't call systemd!)::

    reprozip trace /etc/init.d/mysql start

or the binary (you will have to figure out the right options...)::

    reprozip trace /usr/bin/mysqld

Can I pack a client-server scenario?
====================================

Yes! Note however that only tracing the client will not capture the full story.

The easiest way is to write a script that starts the server, runs your client(s), then shuts down the server; see :ref:`Further considerations when packing <packing-further>`.

Can I pack interactive tools?
=============================

ReproUnzip should have no problem with experiment that interact with the user through the terminal. If your experiment runs until it receives Ctrl+C, that is fine too; ReproZip won't interfere unless you press Ctrl+C twice, stopping the experiment.

Running GUI tools (connecting to an X server) isn't supported by ReproUnzip so far, but we are planning on it.

Can ReproZip pack a database?
=============================

ReproZip can trace a database *server*, however because of the format it uses to store data, it might be hard for you to control exactly what data will be packed. You also probably want to pack all the data from the databases/tables your experiment uses, and not just the pages that were touched while tracing; you can do that by inspecting the configuration file and adding the relevant patterns, for example::

    additional_patterns:
      - /var/lib/mysql/**

What if my experiment runs on a distributed environment?
========================================================

ReproZip cannot trace across multiple machines. You can however trace each component separately, but ReproUnzip has no support to help you setup these multiple machines in the right way from the multiple ``.rpz`` files you will get this way. In particular, you will probably need to set up the same network for the components to talk to each other.

..  _scp-py3:

I have trouble with *reprounzip-vagrant* on Python 3
====================================================

The *reprounzip-vagrant* plugin is compatible with Python 3, however the **scp.py** library used to transfer files has a number of issues. Until the maintainer accepts our patch, you can install our fixed version from Github using::

    pip install 'git+https://github.com/remram44/scp.py.git#egg=scp'

ReproUnzip shows ``running in chroot, ignoring request``
========================================================

This message comes from the systemd client. Using systemd in your experiments is not a good idea and will probably not work. This experiment should be repacked without using systemd, see the :ref:`corresponding section <systemd>`.
