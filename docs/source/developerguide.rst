..  _develop-plugins:

Developer's Guide
*****************

General Development Information
-------------------------------

Development happens on `Github <https://github.com/ViDA-NYU/reprozip>`_; bug reports of feature requests are welcome. If you are interested in giving a hand, please do not hesitate to submit a pull request there.

Continuous testing is provided by `Travis CI <https://travis-ci.org/ViDA-NYU/reprozip>`_. Note that ReproZip supports both Python 2 and 3. Note that test coverage is not very high, this is because a lot of operations are difficult to cover on Travis (Vagrant VMs and Docker containers can't be used over there).

If you have questions or need help with the development of an unpacker or plugin, don't hesitate to use the development mailing-list at `reprozip-dev@vgc.poly.edu`.

Writing Unpackers
-----------------

ReproZip is divided in two steps. Packing gives out a generic package containing the trace SQLite database, YAML configuration file (listing the paths, packages, and run metadata like command-line, environment variables, and input/output files) and actual files, and then in a second step that pack can be turned into a runnable form by reprounzip. This allows for the selection of the unpacker to be left to the reproducer, and also means that when a new unpacker comes out, people will be able to use it on their old packs without change.

The ViDA group maintains different unpackers: the two defaults ones (``directory`` and ``chroot``), ``vagrant`` (distributed as `reprounzip-vagrant <https://pypi.python.org/pypi/reprounzip-vagrant>`_) and ``docker`` (distributed as `reprounzip-docker <https://pypi.python.org/pypi/reprounzip-docker>`_). However, the interface has been thought so that new unpackers could be added easily. While taking a look at the "official" unpackers' source is probably a good idea, this page gives some useful information about how they work.

Structure
'''''''''

An unpacker is a Python module. It can be distributed separately or be part of a bigger distribution; it just has to be declared in that distribution's setup.py as an entry_point to be registered with pkg_resources (see `setuptools' dynamic discovery of services and plugins <https://pythonhosted.org/setuptools/setuptools.html#dynamic-discovery-of-services-and-plugins>`_ section). You should declare a function as entry_point ``reprounzip.unpackers``. The name of the entry_point (the part before ``=``) will be the reprounzip subcommand, and the value is a callable that will get called with the :class:`argparse.ArgumentParser` object for that subcommand.

The package :mod:`reprounzip.unpackers` is a namespace package, so you should be able to add your own unpackers in there should you want to. Please remember to put the correct code in the ``__init__.py`` file (which you can copy from `here <https://github.com/ViDA-NYU/reprozip/blob/master/reprounzip/reprounzip/unpackers/__init__.py>`_) so namespace packages work correctly.

The modules :mod:`reprounzip.common`, :mod:`reprounzip.utils` and :mod:`reprounzip.unpackers.common` contain utilities that you might want to use (make sure to list reprounzip as a requirement in your ``setup.py``).

Example ``setup.py``::

    setup(name='reprounzip-vagrant',
          namespace_packages=['reprounzip', 'reprounzip.unpackers'],
          install_requires=['reprounzip>=0.4'],
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

If these commands can be broken down into different steps that you want to expose to the user, or if you provide completely different actions from these defaults, you are free to add them to the parser as well. For instance, reprounzip-vagrant exposes ``setup/start`` which starts or resume the virtual machine, and ``destroy/vm`` which stops and deallocates the virtual machine but leaves the template for possible reuse.

A note on file paths
''''''''''''''''''''

ReproZip supports Python 2 and 3, is portable to different operating systems, and is meant to accept a wide variety of configurations so that it is compatible with any experiment out there. Even trickier, reprounzip-vagrant needs to manipulate POSIX filenames on Windows, for example in the unpacker.

Because of that, the `rpaths <https://github.com/remram44/rpaths>`_ library is used everywhere internally. You should make sure to use the correct type of path (either :class:`~rpaths.PosixPath` or :class:`~rpaths.Path`) and to cast these to the type Python functions expect, keeping in mind 2/3 differences (most certainly either ``filename.path`` or ``str(filename)``).

Unpacker directory format
'''''''''''''''''''''''''

Unpackers usually create a directory with all that is needed to later run the experiment. This directory is created by the ``setup`` operation, cleaned up by ``destroy``, and is the argument to every command. For example with reprounzip-vagrant::

    $ reprounzip vagrant setup someexperiment.rpz mydirectory
    $ reprounzip vagrant upload mydirectory /tmp/replace.txt:input_text

"Official" unpackers unpack the config.yml file to the root of that directory, and keep status information in a .reprounzip file, a dict in :mod:`pickle` format. Following this same structure will allow the ``showfiles`` command and :class:`~reprounzip.unpackers.common.FileUploader` and :class:`~reprounzip.unpackers.common.FileDownloader` classes to work automatically, so you should try to stick to it.

Signals
'''''''

Since version 0.4.1, reprounzip has signals that can be used to hook in plugins, although no such plugin has been released at this time. To ensure that these work correctly when using your unpacker, you should emit them when appropriate. The complete list of signals is in `signal.py <https://github.com/ViDA-NYU/reprozip/blob/master/reprounzip/reprounzip/signals.py>`_.

Final notes
-----------

After reading this manual, reading the source code of one of the "official" unpackers is probably the best way of understanding how to write your own. They should be short enough to be easy to grasp. Should you have additional questions, don't hesitate to ask on the development mailing-list: `reprozip-dev@vgc.poly.edu`.
