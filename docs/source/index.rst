ReproZip's Documentation
************************

Welcome to ReproZip's documentation!

`ReproZip <http://vida-nyu.github.io/reprozip/>`_ is a tool aimed at simplifying the process of creating reproducible experiments from *command-line executions* (batch executions in the command-line interface). It tracks operating system calls and creates a package that contains all the binaries, files, and dependencies required to run a given command on the author's computational environment. A reviewer can then extract the experiment in his environment to reproduce the results, even if the environment has a different operating system from the original one.

Concretely, ReproZip has two main steps:

- The **Packing Step** happens in the original environment, and generates a compendium of the experiment, so as to make it reproducible. ReproZip tracks operating system calls while executing the experiment, and creates a ``.rpz`` file, which contains all the necessary information and components for the experiment. For more information about the packing step, see :ref:`packing-experiments`.
- The **Unpacking Step** actually reproduces the experiment from the ``.rpz`` file. ReproZip offers different unpackers, from simply unpacking the files in a directory to starting a full virtual machine, which can be used interchangeably from the same packed experiment. It can also automatically substitute input files and command-line arguments. Note that this step is also available on Windows and Mac OS X, since ReproZip can unpack the experiment in a virtual machine for further reproduction. For more information about the unpacking step, see :ref:`unpacking-experiments`.

Contents
--------

..  toctree::
    :maxdepth: 2

    reprozip
    install
    packing
    unpacking
    faq
    developerguide

Links
-----

* `Project website <http://vida-nyu.github.io/reprozip/>`_
* `Github repository <https://github.com/ViDA-NYU/reprozip>`_
