
Using *reprozip*
****************

The *reprozip* component is responsible for packing
an experiment. In ReproZip, we assume that the
experiment can be executed by a single command line,
preferably with no GUI involved
(please refer to `Additional Information`_ for further information
regarding different types of experiment).


There are mainly three steps when packing an experiment with *reprozip*:
(i) tracing the experiment,
(ii) editing the configuration file, if necessary, and
(iii) creating the reproducible package for the experiment.
Each of these steps are explained in more details below.
Note that *reprozip* is only available for Linux distributions.

Tracing an Experiment
=====================

First, *reprozip* needs to trace the operating system calls used
by the experiment, so as to identify all the necessary
information for its future re-execution, such as binaries, files,
library dependencies, and enviroment variables.

The following command is used to trace an experiment::

  $ reprozip trace <command-line>
  
where *<command-line>* is the command line used to execute the
experiment. Internally, *reprozip* executes the experiment
and uses *ptrace* to trace all the system calls issued;
the information captured by *ptrace* is analyzed and
stored in a SQLite database.

The database, together with a *configuration file*,
are placed in a directory named *.reprozip*,
created in the current path where the command was issued.

Editing the Configuration File
==============================



Creating a Package
==================



Example
=======



Additional Information
======================


