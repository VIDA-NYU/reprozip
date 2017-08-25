import argparse

from reprounzip.unpackers.common import COMPAT_OK


def show_vis(args):
    TODO


def setup_vis(parser, **kwargs):
    """Visualizes the provenance of a package as a D3 graph in the browser.
    """
    parser.add_argument(
        'pack', nargs=argparse.OPTIONAL,
        help="Pack to visualize")
    parser.set_defaults(func=show_vis)

    return {'test_compatibility': COMPAT_OK}
