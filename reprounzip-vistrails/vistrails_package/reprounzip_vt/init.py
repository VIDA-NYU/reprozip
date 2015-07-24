# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

from __future__ import division

import os
import pickle
import subprocess
import sys

from vistrails.core.modules.vistrails_module import Module, ModuleError

from . import configuration


REPROUNZIP_VISTRAILS_INTERFACE_VERSION = '1'


class Experiment(object):
    def __init__(self, path, unpacker):
        self.path = path
        self.unpacker = unpacker


class Directory(Module):
    """This represents an experiment that has been unpacked.

    It can be fed through Run modules to run steps of the experiment.
    """
    _input_ports = [('directory', '(basic:Path)')]
    _output_ports = [('experiment', '(Directory)')]

    def compute(self):
        path = self.get_input('directory').name

        if not os.path.exists(path):
            self.setup_experiment()
        if (not os.path.exists(os.path.join(path, 'config.yml')) or
                not os.path.exists(os.path.join(path, '.reprounzip'))):
            raise ModuleError(self,
                              "Directory doesn't contain the necessary file; "
                              "is an experiment set up there?")
        with open(os.path.join(path, '.reprounzip'), 'rb') as fp:
            unpacked_info = pickle.load(fp)
        unpacker = unpacked_info['unpacker']

        self.set_output('experiment', Experiment(path, unpacker))

    def setup_experiment(self):
        raise ModuleError(self, "Experiment directory does not exist")


class UnpackDirectory(Directory):
    """This sets up an experiment from a .RPZ file if it isn't already.

    If the directory exists, this behaves like the Directory module; else it
    will set up the given .RPZ pack with the given unpacker.
    """
    _input_ports = [('pack', '(basic:File)'),
                    ('unpacker', '(basic:String)')]

    def setup_experiment(self):
        raise NotImplementedError


class Run(Module):
    """Runs one step of an experiment, opt. uploading and downloading files.

    Because each experiment requires different files, this uses additional
    ports for them. Creating a Run module might be a bit tedious, but the
    reprounzip-vistrails plugin should generate a template pipeline with all
    the step modules when unpacking an experiment.
    """
    _input_ports = [('experiment', Directory),
                    ('run_number', '(basic:Integer)'),
                    ('cmdline', '(basic:String)')]
    _output_ports = [('experiment', Directory),
                     ('stdout', '(basic:File)'),
                     ('stderr', '(basic:File)')]

    def __init__(self):
        Module.__init__(self)
        self.input_ports_order = []
        self.output_ports_order = []

    def transfer_attrs(self, module):
        Module.transfer_attrs(self, module)
        self.input_ports_order = [p.name for p in module.input_port_specs]
        self.output_ports_order = [p.name for p in module.output_port_specs
                                   if p.name in module.connected_output_ports]

    def compute(self):
        experiment = self.get_input('experiment')

        # python -m reprounzip.plugins.vistrails <unpacker> <target> <run_id>
        # --input-file <na>:<a> --output-file <nb>:<b> --cmdline <c>
        if configuration.check('reprounzip_python'):
            python = configuration.reprounzip_python
        else:
            python = 'python'

        stdout = self.interpreter.filePool.create_file(prefix='vt_rpz_stdout_',
                                                       suffix='.txt')
        stderr = self.interpreter.filePool.create_file(prefix='vt_rpz_stderr_',
                                                       suffix='.txt')

        args = [python, '-m', 'reprounzip.plugins.vistrails',
                REPROUNZIP_VISTRAILS_INTERFACE_VERSION,
                experiment.unpacker, experiment.path,
                '%d' % self.get_input('run_number')]
        for name in self.input_ports_order:
            if self.has_input(name):
                args.append('--input-file')
                args.append('%s:%s' % (name, self.get_input(name).name))
        output_ports = []
        for name in self.output_ports_order:
            f = self.interpreter.filePool.create_file(prefix='vt_rpz_out_')
            args.append('--output-file')
            args.append('%s:%s' % (name, f.name))
            output_ports.append((name, f))

        with open(stdout.name, 'wb') as stdout_fp:
            with open(stderr.name, 'wb') as stderr_fp:
                proc = subprocess.Popen(args,
                                        )#stdout=stdout_fp, stderr=stderr_fp)

        with open(stderr.name, 'rb') as stderr_fp:
            while True:
                chunk = stderr_fp.read(4096)
                if not chunk:
                    break
                sys.stderr.write(chunk)

        if proc.wait() != 0:
            raise ModuleError(self,
                              "Plugin returned with code %d" % proc.returncode)

        for name, file in output_ports:
            self.set_output(name, file)

        self.set_output('experiment', experiment)


_modules = [Directory, Run]
# TODO: UnpackDirectory
