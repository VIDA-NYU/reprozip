..  _develop-plugins:

Developer's Guide
*****************

General Development Information
-------------------------------

Development happens on `Github <https://github.com/ViDA-NYU/reprozip>`_; bug reports of feature requests are welcome. If you are interested in giving a hand, please do not hesitate to submit a pull request there.

Continuous testing is provided by `Travis CI <https://travis-ci.org/ViDA-NYU/reprozip>`_. Note that ReproZip supports both Python 2 and 3. Note that test coverage is not very high, this is because a lot of operations are difficult to cover on Travis (Vagrant VMs and Docker containers can't be used over there).

Writing Unpackers
-----------------

ReproZip is divided in two steps. Packing gives out a generic package containing the trace SQLite database, YAML configuration file (listing the paths, packages, and run metadata like command-line, environment variables, and input/output files) and actual files, and then in a second step that pack can be turned into a runnable form by reprounzip. This allows for the selection of the unpacker to be left to the reproducer, and also means that already-created packs can be used by new unpackers.

The ViDA group maintains different unpackers: the two defaults ones (``directory`` and ``chroot``), ``vagrant`` (distributed as `reprounzip-vagrant <https://pypi.python.org/pypi/reprounzip-vagrant>`_) and ``docker`` (distributed as `reprounzip-docker <https://pypi.python.org/pypi/reprounzip-docker>`_). However, the interface has been thought so that new unpackers could be added easily. While you should probably take a look at the "official" unpackers, this page gives so useful information about how they work.

Structure
'''''''''

An unpacker is a Python module. It can be distributed separately or be part of a bigger distribution; it just has to be declared in that distribution's setup.py as an entry_point to be registered with pkg_resources (see `setuptools' dynamic discovery of services and plugins <https://pythonhosted.org/setuptools/setuptools.html#dynamic-discovery-of-services-and-plugins>`_ section). You should declare a function as entry_point ``reprounzip.unpackers``. The name of the entry_point (the part before ``=``) will be the reprounzip subcommand, and the value is a callable that will get called with the :class:`argparse.ArgumentParser` object for that subcommand.

Example ``setup.py``::

    setup(name='reprounzip-vagrant',
          entry_points={
              'reprounzip.unpackers': [
                  'vagrant = reprounzip.unpackers.vagrant:setup'
                  # The setup() function sets up the parser for reprounzip vagrant
              ]
          }
          # ...
    )

Usual commands
''''''''''''''

If possible, you should try to follow the same command names that the official unpackers use; these are:

* ``setup``, to create the unpacked directory and set everything up for execution;
* ``run``, to execute the experiment;
* ``destroy``, to bring down all that setup had to prepare and delete the unpacked directory safely;
* ``upload`` and ``download``, to either substitute input files in the experiment with your own, or get the output files out for further examination.

These commands can be broken down in different steps that you want to expose to the user, or completely different actions, you are free to add them to the parser as well. For instance, reprounzip-vagrant exposes ``setup/start`` which starts or resume the virtual machine, and ``destroy/vm`` which stops and deallocates the virtual machine but leaves the template for possible reuse.
