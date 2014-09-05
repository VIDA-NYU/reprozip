[![Build Status](https://travis-ci.org/ViDA-NYU/reprozip.svg?branch=master)](https://travis-ci.org/ViDA-NYU/reprozip)
[![Coverage Status]
(https://coveralls.io/repos/ViDA-NYU/reprozip/badge.png?branch=master)]
(https://coveralls.io/r/ViDA-NYU/reprozip?branch=master)

ReproZip
========

ReproZip is a tool aimed at simplifying the process of creating reproducible
experiments from command-line executions, a frequently-used common denominator
in computational science. It tracks operating system calls and creates a package
that contains all the binaries, files and dependencies required to run a given
command on the author's computational environment (packing step).
A reviewer can then extract the experiment in his environment to reproduce the results (unpacking step).

For more detailed information, please refer to our [website][web] as well as
our [documentation][docs].

ReproZip is currently being developed at [NYU][nyu]. The team includes:

* [Fernando Chirigati][fc]
* [Rémi Rampin][rr]
* [Dennis Shasha][ds]
* [Juliana Freire][jf]


[vagrant]: http://www.vagrantup.com/
[docs]: http://reprozip.readthedocs.org/
[web]: http://vida-nyu.github.io/reprozip/
[pz]: https://pypi.python.org/pypi/reprozip
[puz]: https://pypi.python.org/pypi/reprounzip
[puzd]: https://pypi.python.org/pypi/reprounzip-docker
[puzv]: https://pypi.python.org/pypi/reprounzip-vagrant
[fc]: http://vgc.poly.edu/~fchirigati/
[rr]: https://www.linkedin.com/profile/view?id=98448601
[jf]: http://vgc.poly.edu/~juliana/
[ds]: http://cs.nyu.edu/shasha/
[nyu]: http://engineering.nyu.edu/