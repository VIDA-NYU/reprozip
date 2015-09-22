..  _vistrails:

VisTrails Plugin
****************

The `reprounzip-vistrails` plugin is not an unpacker in itself, it interacts with the existing unpackers to generate and execute VisTrails workflows. It will allow you to run unpacked ReproZip experiments, as well as replace input files and get output files from them.

reprounzip-vistrails setup
==========================

..  note:: This plugin is **not** distributed with `reprounzip`; it is a separate package that should be installed before use (see :ref:`install`).

Once the plugin is installed, a VisTrails workflow will be generated every time you unpack an experiment. You don't need VisTrails on your machine for this to work. This workflow only contains the reference to the unpacked directory and modules calling each run in sequence; running the workflow is thus the same as running the full experiment (except that VisTrails will cache).

Note that this does mean that a workflow needs to be updated with the correct path to the unpacked experiment, should you unpack it somewhere else or send the workflow file to another machine.

VisTrails setup
===============

To run the workflow, you will need VisTrails on your machine and the ReproUnzip package, which is present in VisTrails 2.2.3 and up. If you used the installer for either VisTrails or ReproUnzip, you will need to set the path to ReproUnzip's Python interpreter in VisTrails's package configuration dialog:

..  figure:: figures/vistrails-config.png
    :align: center

For example, this will be ``/opt/reprounzip/python27/bin/python`` if you used the Mac OS X installer, and something like ``C:\Program Files (x86)\ReproUnzip\python2.7\python.exe`` if you used the Windows installer.

Usage
=====

The easiest way to use the ReproUnzip plugin is to just start from the workflow that is auto-generated when you unpack an experiment.

..  figure:: figures/vistrails-gene.png
    :align: center

You can see here the ``Directory`` module which refers to the experiment. That directory is passed from module to module to represent the changes in the environment, since each ``Run`` module will change the internal state of the machine.

The ports beside the experiment directory represent the input and output files that are used by this particular run. The module also exposes the command-line, should you want to change a parameter or tweak the flags there.

Note that it is possible that a file exposed as an output port in one ``Run`` module is the input port of the next ``Run`` module, and yet these are not connected. This will still work since the whole machine state is carried to the next execution; connecting here would work, but would make ReproUnzip download the file to VisTrails just to upload it again in the same location. You can speed up the workflow by not connecting the files that you don't examine or change, since downloading and uploading take time.
