ReproZip's Documentation
************************

Welcome to ReproZip's documentation!

`ReproZip <https://vida-nyu.github.io/reprozip/>`__ is a tool aimed at simplifying the process of creating reproducible experiments from *command-line executions*. It tracks operating system calls and creates a package that contains all the binaries, files, and dependencies required to run a given command on the author's computational environment. A reviewer can then extract the experiment in his own environment to reproduce the results, even if the environment has a different operating system from the original one.

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
    vistrails
    faq
    troubleshooting
    unpacked-format
    developerguide
    glossary

Links
-----

* `Project website <https://vida-nyu.github.io/reprozip/>`__
* `GitHub repository <https://github.com/ViDA-NYU/reprozip>`__
* Mailing lists:

  * `reprozip-users@vgc.poly.edu <https://vgc.poly.edu/mailman/listinfo/reprozip-users>`__ (users)

  * `reprozip-dev@vgc.poly.edu <https://vgc.poly.edu/mailman/listinfo/reprozip-dev>`__ (developers)
