[![Build Status](https://github.com/VIDA-NYU/reprozip/workflows/Test/badge.svg)](https://github.com/VIDA-NYU/reprozip/actions)
[![Coverage Status](https://codecov.io/github/VIDA-NYU/reprozip/coverage.svg?branch=master)](https://codecov.io/github/VIDA-NYU/reprozip?branch=master)
[![Documentation Status](https://readthedocs.org/projects/reprozip/badge/?version=master)](https://docs.reprozip.org/en/master/)
[![Matrix](https://img.shields.io/badge/chat-matrix.org-blue.svg)](https://riot.im/app/#/room/#reprozip:matrix.org)
[![paper](https://img.shields.io/badge/JOSS-10.21105%2Fjoss.00107-green.svg)](http://joss.theoj.org/papers/b578b171263c73f64dfb9d040ca80fe0)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.10291844-green.svg)](https://doi.org/10.5281/zenodo.10291844)

ReproZip
========

[ReproZip][web] is a tool aimed at simplifying the process of creating reproducible experiments from command-line executions, a frequently-used common denominator in computational science.

It tracks operating system calls and creates a package that contains all the binaries, files and dependencies required to run a given command on the author's computational environment (packing step). A reviewer can then extract the experiment in his environment to reproduce the results (unpacking step).

Quickstart
----------

We have an [example repository](https://github.com/VIDA-NYU/reprozip-examples) with a variety of different software. Don't hesitate to check it out, and contribute your own example if use ReproZip for something new!

### Packing

Packing experiments is only available for Linux distributions. In the environment where the experiment is originally executed, first install reprozip:

    $ pip install reprozip

Then, run your experiment with reprozip. Suppose you execute your experiment by originally running the following command:

    $ ./myexperiment -my --options inputs/somefile.csv other_file_here.bin

To run it with reprozip, you just need to use the prefix *reprozip trace*:

    $ reprozip trace ./myexperiment -my --options inputs/somefile.csv other_file_here.bin

This command creates a *.reprozip-trace* directory, in which you'll find the configuration file, named *config.yml*. You can edit the command line and environment variables, and choose which files to pack.

If you are using Debian or Ubuntu, most of these files (library dependencies) are organized by package. You can add or remove files, or choose not to include a package by changing option *packfiles* from true to false. In this way, smaller packs can be created with reprozip (if space is an issue), and reprounzip can download these files from the package manager; however, note this is only available for Debian and Ubuntu for now, and also be aware that package versions might differ. Choosing which files to pack is also important to remove sensitive information and third-party software that is not open source and should not be distributed.

Once done editing the configuration file (or even if you did not change anything), run the following command to create a ReproZip package named *my_experiment*:

    $ reprozip pack my_experiment.rpz

Voil&agrave;! Now your experiment has been packed, and you can send it to your collaborators, reviewers, and researchers around the world!

Note that you can open the help message for any reprozip command by using the flag *-h*.

### Unpacking

Do you need to unpack an experiment in a Linux machine? Easy! First, install reprounzip:

    $ pip install reprounzip

Then, if you want to unpack everything in a single directory named *mydirectory* and execute the experiment from there, use the prefix *reprounzip directory*:

    $ reprounzip directory setup my_experiment.rpz mydirectory
    $ reprounzip directory run mydirectory

In case you prefer to build a chroot environment under *mychroot*, use the prefix *reprounzip chroot*:

    $ reprounzip chroot setup my_experiment.rpz mychroot
    $ reprounzip chroot run mychroot

Note that the previous options do not interfere with the original configuration of the environment, so don't worry! If you are using Debian or Ubuntu, reprounzip also has an option to install all the library dependencies directly on the machine using package managers (rather than just copying the files from the .rpz package). Be aware that this will interfere in your environment and it may update your library packages, so use it at your own risk! For this option, just use the prefix *reprounzip installpkgs*:

    $ reprounzip installpkgs my_experiment.rpz

What if you want to reproduce the experiment in Windows or Mac OS X? You can build a virtual machine with the experiment! Easy as well! First, install the plugin reprounzip-vagrant:

    $ pip install reprounzip-vagrant

Note that (i) you must install reprounzip first, and (ii) the plugin requires having [Vagrant][vagrant] installed. Then, use the prefix *reprounzip vagrant* to create and start a virtual machine under directory *mytemplate*:

    $ reprounzip vagrant setup my_experiment.rpz mytemplate

To execute the experiment, simply run:

    $ reprounzip vagrant run mytemplate

Alternatively, you may use [Docker][docker] containers to reproduce the experiment, which also works under Linux, Mac OS X, and Windows! First, install the plugin reprounzip-docker:

    $ pip install reprounzip-docker

Then, assuming that you want to create the container under directory *mytemplate*, simply use the prefix *reprounzip docker*:

    $ reprounzip docker setup my_experiment.rpz mytemplate
    $ reprounzip docker run mytemplate

Remember that you can open the help message and learn more about other available flags and options by using the flag *-h* for any reprounzip command.

Citing ReproZip
---------------

Please use the following when citing ReproZip ([BibTeX](CITATION.txt)):

    ReproZip: Computational Reproducibility With Ease
    F. Chirigati, R. Rampin, D. Shasha, and J. Freire.
    In Proceedings of the 2016 ACM SIGMOD International Conference on Management of Data (SIGMOD), pp. 2085-2088, 2016

Contribute
----------

Please subscribe to and contact the [reprozip@nyu.edu](https://groups.google.com/a/nyu.edu/g/reprozip) mailing list for questions, suggestions and discussions about using reprozip.

Bugs and feature plannings are tracked in the [GitHub issues](https://github.com/VIDA-NYU/reprozip/issues). Feel free to add an issue!

To suggest changes to this source code, feel free to raise a [GitHub pull request](https://github.com/VIDA-NYU/reprozip/pulls).  Any contributions received are assumed to be covered by the [BSD 3-Clause license](LICENSE.txt). We might ask you to sign a _Contributor License Agreement_ before accepting a larger contribution.

License
-------

* Copyright (C) 2014, New York University

Licensed under a **BSD 3-Clause license**. See the file [LICENSE.txt](LICENSE.txt) for details.

Links and References
--------------------

For more detailed information, please refer to our [website][web], as well as to our [documentation][docs].

ReproZip is currently being developed at [NYU][nyu]. The team includes:

* [Fernando Chirigati][fc]
* [Juliana Freire][jf]
* [Rémi Rampin][rr]
* [Dennis Shasha][ds]
* [Vicky Rampin][vr]

[vagrant]: https://www.vagrantup.com/
[docker]: https://www.docker.com/
[docs]: https://docs.reprozip.org/
[web]: https://www.reprozip.org/
[pz]: https://pypi.python.org/pypi/reprozip
[puz]: https://pypi.python.org/pypi/reprounzip
[puzd]: https://pypi.python.org/pypi/reprounzip-docker
[puzv]: https://pypi.python.org/pypi/reprounzip-vagrant
[fc]: http://fchirigati.com/
[jf]: https://vgc.poly.edu/~juliana/
[rr]: https://remi.rampin.org/
[ds]: http://cs.nyu.edu/shasha/
[vr]: https://vicky.rampin.org/
[nyu]: http://engineering.nyu.edu/
