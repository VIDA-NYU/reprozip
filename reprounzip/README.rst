ReproZip is a tool aimed at scientists using Linux distributions, that
simplifies the process of creating reproducible experiments from programs.

It uses the ptrace facilities of Linux to trace the processes and files that
are part of the experiment and build a comprehensive provenance graph for the
user to review.

Then, it can pack these files in a package to allow for easy reproducibility
elsewhere, either by unpacking and running on a compatible machine or by
creating a virtual machine through Vagrant.

http://vida-nyu.github.io/reprozip/

Quickstart
==========

Packing
-------

On the machine where the experiment is setup, install reprozip::

    $ pip install reprozip

Then run your experiment under reprozip's monitoring (simply prefix `reprozip trace`)::

    $ reprozip trace ./myexperiment -my --options inputs/somefile.csv other_file_here.bin

This leaves you with a `.reprozip` directory, in which you'll find the `config.yml` configuration file. In it, you can edit the command-line and environment variables, and choose which files are to be packed.

If you are using one of the supported Linux distributions (currently Debian and Ubuntu), these files are organized by package, plus an `other_files:` section at the end. You can add or remove files, or choose not to include a package by changing `packfiles: true` to `packfiles: false`; this allows you to make a smaller packs, since reprounzip can get these files from the package manager easily (however versions might differ).

Once done editing `.reprozip/config.yml`, or if you left everything as-is, simply run the packer: (note that you should review the configuration to be sure not to include sensitive information)

::

    $ reprozip pack my_experiment.rpz

Unpacking
---------

::

    $ pip install reprounzip

    # Installing the packages on the host machine
    $ reprounzip installpkgs my_experiment.rpz
    # Unpacking in a directory
    $ reprounzip directory my_experiment.rpz mydirectory
    $ mydirectory/script.sh
    # Building a chroot environment
    $ reprounzip chroot my_experiment.rpz mychroot
    $ sudo mychroot/script.sh

    # Building a virtual machine (requires Vagrant)
    $ pip install reprounzip-vagrant
    $ reprounzip vagrant --use-chroot my_experiment.rpz mytemplate
    $ cd mytemplate; vagrant up
    $ vagrant ssh
    vagrant@vm$ sh /vagrant/script.sh

Links and references
====================

This package holds the unpacker components (and the 'reprounzip' command-line
utility); see `reprozip <https://pypi.python.org/pypi/reprozip>`_ for the packer (which only works on Linux).

* Github page: https://github.com/ViDA-NYU/reprozip
* Bug tracker: https://github.com/ViDA-NYU/reprozip/issues
* Contact us at reprozip-users@vgc.poly.edu

ReproZip is currently being developed at `NYU <http://engineering.nyu.edu/>`_. The team includes:

* Fernando Chirigati
* Rémi Rampin
* Dennis Shasha
* Juliana Freire

Publications:

* TaPP 2013: http://vgc.poly.edu/~fchirigati/papers/chirigati-tapp2013.pdf
* SIGMOD 2013: http://vgc.poly.edu/~fchirigati/papers/chirigati-sigmod2013.pdf
