ReproZip's Documentation
************************

Welcome to ReproZip's documentation!

`ReproZip <https://www.reprozip.org/>`__ is a tool aimed at simplifying the process of creating reproducible experiments from *command-line executions*. It tracks operating system calls and creates a bundle that contains all the binaries, files, and dependencies required to run a given command on the author's computational environment. A reviewer can then extract the experiment in his own environment to reproduce the results, even if the environment has a different operating system from the original one.

Currently, ReproZip can only pack experiments that originally run on Linux.

Concretely, ReproZip has two main steps:

- The :ref:`packing step <packing>` happens in the original environment, and generates a compendium of the experiment so as to make it reproducible. ReproZip tracks operating system calls while executing the experiment, and creates a ``.rpz`` file, which contains all the necessary information and components for the experiment.
- The :ref:`unpacking step <unpacking>` reproduces the experiment from the ``.rpz`` file. ReproZip offers different unpacking methods, from simply decompressing the files in a directory to starting a full virtual machine, and they can be used interchangeably from the same packed experiment. It is also possible to automatically replace input files and command-line arguments. Note that this step is also available on Windows and Mac OS X, since ReproZip can unpack the experiment in a virtual machine for further reproduction.

Contents
--------

..  toctree::
    :maxdepth: 2

    reprozip
    install
    packing
    unpacking
    graph
    jupyter
    gui
    vistrails
    faq
    troubleshooting
    unpacked-format
    developerguide
    glossary

Links
-----

* `Project website <https://www.reprozip.org/>`__
* `GitHub repository <https://github.com/VIDA-NYU/reprozip>`__
* Mailing list: `reprozip@nyu.edu <https://groups.google.com/a/nyu.edu/g/reprozip>`__
