import traceback
import warnings

from reprounzip.utils import irange, iteritems


class Signal(object):
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
                    warnings.warn("Missing required argument %s; signal "
                                  "ignored" % arg,
                                  stacklevel=2)
                    return
            else:
                if arg in kwargs:
                    info[arg] = kwargs.pop(arg)
                    if argtype == Signal.DEPRECATED:
                        warnings.warn("Argument %s is deprecated" % arg,
                                      stacklevel=2)
        if kwargs:
            warnings.warn("Unexpected argument %s; signal ignored" % arg,
                          stacklevel=2)
            return

        for listener in self._listeners:
            try:
                listener(info)
            except Exception:
                traceback.print_exc()

    def subscribe(self, func):
        if not callable(func):
            raise TypeError("%r object is not callable" % type(func))
        self._listeners.add(func)

    def unsubscribe(self, func):
        self._listeners.discard(func)


pre_setup = Signal(['target', 'pack'])
post_setup = Signal(['target'])
pre_destroy = Signal(['target'])
post_destroy = Signal(['target'])
pre_run = Signal(['target'])
post_run = Signal(['target', 'retcode'])
application_finishing = Signal(['reason'])


unpacker = None
