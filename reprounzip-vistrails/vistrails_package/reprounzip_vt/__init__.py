# Copyright (C) 2014-2015 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""VisTrails package for reprounzip.

This package is the component loaded by VisTrails that provide the
reprounzip modules. A separate component, reprounzip-vistrails, is a plugin for
reprounzip that creates VisTrails pipelines that use this package.
"""

from __future__ import division

from vistrails.core.configuration import ConfigurationObject


identifier = 'io.github.vida-nyu.reprozip.reprounzip'
name = 'reprounzip'
version = '0.1'


configuration = ConfigurationObject(reprounzip_python='python')
