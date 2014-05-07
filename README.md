[![Build Status](https://travis-ci.org/remram44/reprozip-ptrace.svg?branch=master)](https://travis-ci.org/remram44/reprozip-ptrace)

reprozip-ptrace
===============

This is a rework of [ReproZip][fc] using ptrace instead of [systemtap][stap],
since it is difficult to setup and use.

ReproZip
--------

ReproZip is a tool aimed at scientists using Linux distributions, that
simplifies the process of creating reproducible experiments from programs.

It uses the ptrace facilities of Linux to trace the processes and files that
are part of the experiment and build a comprehensive provenance graph for the
user to review.

Then, it can pack these files in a package to allow for easy reproducibility
elsewhere, either by unpacking and running on a compatible machine or by
creating a virtual machine through [Vagrant][vagrant].

[fc]: https://github.com/fchirigati/reprozip
[stap]: https://sourceware.org/systemtap/
[vagrant]: http://www.vagrantup.com/
