import contextlib
import unittest
import warnings

from reprounzip import signals
from reprounzip.signals import Signal


class TestSignals(unittest.TestCase):
    @contextlib.contextmanager
    def make_signal(self, *args, **kwargs):
        sig = Signal('testsig', *args, **kwargs)
        self.assertIn('testsig', signals.__dict__)
        self.assertIs(sig, signals.__dict__['testsig'])
        try:
            yield sig
        finally:
            del signals.__dict__['testsig']

    def test_make_signal(self):
        """Tests signal creation."""
        with self.make_signal(['p1', 'p2']):
            pass
        with self.make_signal(['p1'], new_args=['p3'], old_args=['p4']) as sig:
            self.assertEqual(sig._args,
                             {'p1': Signal.REQUIRED,
                              'p3': Signal.OPTIONAL,
                              'p4': Signal.DEPRECATED})
        with self.assertRaises(ValueError):
            with self.make_signal(['p1', 'p2'], new_args=['p2', 'p3']):
                pass

    def test_subscription(self):
        """Tests subscribe() and unsubscribe()."""
        def foo(info):
            pass

        with self.make_signal() as sig:
            sig.subscribe(foo)
            with self.assertRaises(TypeError):
                sig.subscribe(object())
            with self.assertRaises(TypeError):
                sig.subscribe(2)
            sig.unsubscribe(4)
            self.assertEqual(sig._listeners, set([foo]))
            sig.unsubscribe(foo)
            self.assertFalse(sig._listeners)

    def test_calls(self):
        """Tests actually emitting signals."""
        def called(info):
            called.last = info

        def callsig(res_type, **kwargs):
            if res_type not in ('succ', 'warn', 'fail'):
                raise TypeError
            called.last = None
            with warnings.catch_warnings(record=True) as w:
                sig(**kwargs)
            if res_type == 'fail' or res_type == 'warn':
                self.assertEqual(len(w), 1)
            if res_type == 'succ' or res_type == 'warn':
                self.assertEqual(called.last, kwargs)

        with self.make_signal(['a', 'b'],
                              new_args=['c'], old_args=['d']) as sig:
            sig.subscribe(called)

            callsig('succ', a=1, b=2)
            callsig('succ', a=1, b=2, c=3)
            callsig('fail', a=1)
            callsig('warn', a=1, b=2, d=3)
