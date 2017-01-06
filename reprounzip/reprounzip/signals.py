# Copyright (C) 2014-2017 New York University
# This file is part of ReproZip which is released under the Revised BSD License
# See file LICENSE for full license details.

"""Signal system.

Emitting and subscribing to these signals is the framework for the plugin
infrastructure.
"""

from __future__ import division, print_function, unicode_literals

import traceback
import warnings

from reprounzip.utils import irange, iteritems


class SignalWarning(UserWarning):
    """Warning from the Signal class.

    Mainly useful for testing (to turn these to errors), however a 'signal:'
    prefix is actually used in the messages because of Python bug 22543
    http://bugs.python.org/issue22543
    """


class Signal(object):
    """A signal, with its set of arguments.

    This holds the expected parameters that the signal expects, in several
    categories:
    * `expected_args` are the arguments of the signals that must be set. Trying
      to emit the signal without these will show a warning and won't touch the
      listeners. Listeners can rely on these being set.
    * `new_args` are new arguments that listeners cannot yet rely on but that
      emitters should try to pass in. Missing arguments doesn't show a warning
      yet but might in the future.
    * `old_args` are arguments that you might still pass in but that you should
      move away from; they will show a warning stating their deprecation.

    Listeners can subscribe to a signal, and may be any callable hashable
    object.
    """
    REQUIRED, OPTIONAL, DEPRECATED = irange(3)

    def __init__(self, expected_args=[], new_args=[], old_args=[]):
        self._args = {}
        self._args.update((arg, Signal.REQUIRED) for arg in expected_args)
        self._args.update((arg, Signal.OPTIONAL) for arg in new_args)
        self._args.update((arg, Signal.DEPRECATED) for arg in old_args)
        if (len(expected_args) + len(new_args) + len(old_args) !=
                len(self._args)):
            raise ValueError("Repeated argument names")
        self._listeners = set()

    def __call__(self, **kwargs):
        info = {}
        for arg, argtype in iteritems(self._args):
            if argtype == Signal.REQUIRED:
                try:
                    info[arg] = kwargs.pop(arg)
                except KeyError:
                    warnings.warn("signal: Missing required argument %s; "
                                  "signal ignored" % arg,
                                  category=SignalWarning,
                                  stacklevel=2)
                    return
            else:
                if arg in kwargs:
                    info[arg] = kwargs.pop(arg)
                    if argtype == Signal.DEPRECATED:
                        warnings.warn(
                            "signal: Argument %s is deprecated" % arg,
                            category=SignalWarning,
                            stacklevel=2)
        if kwargs:
            arg = next(iter(kwargs))
            warnings.warn(
                "signal: Unexpected argument %s; signal ignored" % arg,
                category=SignalWarning,
                stacklevel=2)
            return

        for listener in self._listeners:
            try:
                listener(**info)
            except Exception:
                traceback.print_exc()
                warnings.warn("signal: Got an exception calling a signal",
                              category=SignalWarning)

    def subscribe(self, func):
        """Adds the given callable to the listeners.

        It must be callable and hashable (it will be put in a set).

        It will be called with the signals' arguments as keywords. Because new
        parameters might be introduced, it should accept these by using::

            def my_listener(param1, param2, **kwargs_):
        """
        if not callable(func):
            raise TypeError("%r object is not callable" % type(func))
        self._listeners.add(func)

    def unsubscribe(self, func):
        """Removes the given callable from the listeners.

        If the listener wasn't subscribed, does nothing.
        """
        self._listeners.discard(func)


pre_setup = Signal(['target', 'pack'])
post_setup = Signal(['target'], ['pack'])
pre_destroy = Signal(['target'])
post_destroy = Signal(['target'])
pre_run = Signal(['target'])
post_run = Signal(['target', 'retcode'])
pre_parse_args = Signal(['parser', 'subparsers'])
post_parse_args = Signal(['args'])
application_finishing = Signal(['reason'])


unpacker = None
