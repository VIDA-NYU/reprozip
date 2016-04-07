[![Build Status](https://travis-ci.org/ViDA-NYU/reprozip.svg?branch=master)]
(https://travis-ci.org/ViDA-NYU/reprozip)
[![Coverage Status]
(http://codecov.io/github/ViDA-NYU/reprozip/coverage.svg?branch=master)]
(http://codecov.io/github/ViDA-NYU/reprozip?branch=master)
[![Code Health](https://landscape.io/github/ViDA-NYU/reprozip/master/landscape.png)](https://landscape.io/github/ViDA-NYU/reprozip/master)
[![Documentation Status](https://readthedocs.org/projects/reprozip/badge/)]
(http://reprozip.readthedocs.org/en/latest/)
[![Gitter](https://badges.gitter.im/ViDA-NYU/reprozip.svg)](https://gitter.im/ViDA-NYU/reprozip?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

ReproZip
========

[ReproZip][web] is a tool aimed at simplifying the process of creating
reproducible experiments from command-line executions, a frequently-used common
denominator in computational science.

It tracks operating system calls and creates a package that contains all the
binaries, files and dependencies required to run a given command on the
author's computational environment (packing step). A reviewer can then extract
the experiment in his environment to reproduce the results (unpacking step).

Quickstart
----------

### Packing

Packing experiments is only available for Linux distributions. In the
environment where the experiment is originally executed, first install
reprozip:

    $ pip install reprozip

Then, run your experiment with reprozip. Suppose you execute your experiment by
originally running the following command:

    $ ./myexperiment -my --options inputs/somefile.csv other_file_here.bin

To run it with reprozip, you just need to use the prefix *reprozip trace*:

    $ reprozip trace ./myexperiment -my --options inputs/somefile.csv other_file_here.bin

This command creates a *.reprozip* directory, in which you'll find the
configuration file, named *config.yml*. You can edit the command line and
environment variables, and choose which files to pack.

If you are using Debian or Ubuntu, most of these files (library dependencies)
are organized by package. You can add or remove files, or choose not to include
a package by changing option *packfiles* from true to false. In this way,
smaller packs can be created with reprozip (if space is an issue), and
reprounzip can download these files from the package manager; however, note
this is only available for Debian and Ubuntu for now, and also be aware that
package versions might differ. Choosing which files to pack is also important
to remove sensitive information and third-party software that is not open
source and should not be distributed.

Once done editing the configuration file (or even if you did not change
anything), run the following command to create a ReproZip package named
*my_experiment*:

    $ reprozip pack my_experiment.rpz

Voil&agrave;! Now your experiment has been packed, and you can send it to your
collaborators, reviewers, and researchers around the world!

Note that you can open the help message for any reprozip command by using the
flag *-h*.

### Unpacking

Do you need to unpack an experiment in a Linux machine? Easy! First, install
reprounzip:

    $ pip install reprounzip

Then, if you want to unpack everything in a single directory named
*mydirectory* and execute the experiment from there, use the prefix *reprounzip
directory*:

    $ reprounzip directory setup my_experiment.rpz mydirectory
    $ reprounzip directory run mydirectory

In case you prefer to build a chroot environment under *mychroot*, use the
prefix *reprounzip chroot*:

    $ reprounzip chroot setup my_experiment.rpz mychroot
    $ reprounzip chroot run mychroot

Note that the previous options do not interfere with the original configuration
of the environment, so don't worry! If you are using Debian or Ubuntu,
reprounzip also has an option to install all the library dependencies directly
on the machine using package managers (rather than just copying the files from
the .rpz package). Be aware that this will interfere in your environment and it
may update your library packages, so use it at your own risk! For this option,
just use the prefix *reprounzip installpkgs*:

    $ reprounzip installpkgs my_experiment.rpz

What if you want to reproduce the experiment in Windows or Mac OS X? You can
build a virtual machine with the experiment! Easy as well! First, install the
plugin reprounzip-vagrant:

    $ pip install reprounzip-vagrant

Note that (i) you must install reprounzip first, and (ii) the plugin requires
having [Vagrant][vagrant] installed. Then, use the prefix *reprounzip vagrant*
to create and start a virtual machine under directory *mytemplate*:

    $ reprounzip vagrant setup my_experiment.rpz mytemplate

To execute the experiment, simply run:

    $ reprounzip vagrant run mytemplate

Alternatively, you may use [Docker][docker] containers to reproduce the
experiment, which also works under Linux, Mac OS X, and Windows! First, install
the plugin reprounzip-docker:

    $ pip install reprounzip-docker

Then, assuming that you want to create the container under directory
*mytemplate*, simply use the prefix *reprounzip docker*:

    $ reprounzip docker setup my_experiment.rpz mytemplate
    $ reprounzip docker run mytemplate

Remember that you can open the help message and learn more about other
available flags and options by using the flag *-h* for any reprounzip command.

Links and References
--------------------

For more detailed information, please refer to our [website][web], as well as
to our [documentation][docs].

ReproZip is currently being developed at [NYU][nyu]. The team includes:

* [Fernando Chirigati][fc]
* [Rémi Rampin][rr]
* [Dennis Shasha][ds]
* [Juliana Freire][jf]

[vagrant]: http://www.vagrantup.com/
[docker]: https://www.docker.com/
[docs]: http://reprozip.readthedocs.org/
[web]: http://vida-nyu.github.io/reprozip/
[pz]: https://pypi.python.org/pypi/reprozip
[puz]: https://pypi.python.org/pypi/reprounzip
[puzd]: https://pypi.python.org/pypi/reprounzip-docker
[puzv]: https://pypi.python.org/pypi/reprounzip-vagrant
[fc]: http://vgc.poly.edu/~fchirigati/
[rr]: http://remram.fr/
[jf]: http://vgc.poly.edu/~juliana/
[ds]: http://cs.nyu.edu/shasha/
[nyu]: http://engineering.nyu.edu/
