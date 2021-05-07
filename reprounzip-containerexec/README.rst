ReproZip
========

`ReproZip <https://www.reprozip.org/>`__ is a tool aimed at simplifying the process of creating reproducible
experiments from command-line executions, a frequently-used common denominator
in computational science. It tracks operating system calls and creates a package
that contains all the binaries, files and dependencies required to run a given
command on the author's computational environment (packing step).
A reviewer can then extract the experiment in his environment to reproduce the results (unpacking step).

reprounzip-containerexec
------------------------

This is the component responsible for the unpacking step.
It uses Linux kernel namespaces to create a container similarly to Docker.
Contrary to Docker, however, it works without installation of additional software
and without root access.
It is based on the tool ``containerexec``, which is part of `BenchExec <https://github.com/sosy-lab/benchexec/>`_.
Please refer to the `documentation <https://github.com/sosy-lab/benchexec/blob/master/doc/container.md>`_
for the system requirements.


Additional Information
----------------------

For more information about ReproZip,
please refer to its `website <https://www.reprozip.org/>`_,
as well as to the `documentation <https://reprozip.readthedocs.io/>`_.

For more information about BenchExec,
please refer to its `website <https://github.com/sosy-lab/benchexec/>`_.
