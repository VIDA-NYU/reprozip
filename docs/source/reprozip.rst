
What is ReproZip?
*****************

The Need for Reproducibility
============================

Reproducibility is a core component of the scientific process: it helps researchers all around the world to verify the results and also to build on them, alowing science to move forward. In natural science, long tradition requires experiments to be described in enough detail so that they can be reproduced by researchers around the world. The same standard, however, has not been widely applied to computational science, where researchers often have to rely on plots, tables, and figures included in papers, which loosely describe the obtained results.

The truth is computational reproducibility can be very painful to achieve for a number of reasons. Take the author-reviewer scenario of a scientific paper as an example. Authors must generate a compendium that encapsulates all the inputs needed to correctly reproduce their experiments: the data, a complete specification of the experiment and its steps, and information about the originating computational environment (OS, hardware architecture, and library dependencies). Keeping track of this information manually is rarely feasible: it is both time-consuming and error-prone. First, computational environments are complex, consisting of many layers of hardware and software, and the configuration of the OS is often hidden. Second, tracking library dependencies is challenging, especially for large experiments. If authors did not plan for reproducibility since the beginning of the project, reproducibility is drastically hampered.

For reviewers, even with a compendium in their hands, it may be hard to reproduce the results. There may be no instructions about how to execute the code and explore it further; the experiment may not run on his operating system; there may be missing libraries; library versions may be different; and several issues may arise while trying to install all the required dependencies, a problem colloquially known as `dependency hell <http://en.wikipedia.org/wiki/Dependency_hell>`_.

Making Reproducibility Easier with ReproZip
===========================================

`ReproZip <http://vida-nyu.github.io/reprozip/>`_ is a tool aimed at simplifying the process of creating reproducible experiments from *command-line executions* (batch executions in the command-line interface), a frequently-used common denominator in computational science. It tracks operating system calls and creates a package that contains all the binaries, files, and dependencies required to run a given command on the author's computational environment. A reviewer can then extract the experiment in his environment to reproduce the results, even if the environment has a different operating system from the original one.

Concretely, ReproZip has two main steps:

- **Packing Step**: This is the step responsible for generating a compendium of the experiment, so as to make it reproducible. ReproZip tracks operating system calls while executing the experiment to detect all its important components, such as binaries, input files, library dependencies, and environment variables. Then, it generates a .rpz file, which represents the experiment package that contains all these necessary components to reproduce it in other environments. Currently, ReproZip uses *ptrace* to track system calls, which means that the packing step is only available for Linux distributions. For more information about the packing step, see :ref:`packing-experiments`.
- **Unpacking Step**: This is the step responsible for unpacking the .rpz file and allowing users to reproduce the experiment. ReproZip offers different unpackers and provides mechanisms to list input and output files, to re-execute the experiment, and to vary the experiment by replacing input files and command line parameters. This step is available not only for Linux distributions but also for Windows and Mac OS X, since ReproZip can unpack the experiment in a virtual machine for further reproduction. For more information about the unpacking step, see :ref:`unpacking-experiments`.
