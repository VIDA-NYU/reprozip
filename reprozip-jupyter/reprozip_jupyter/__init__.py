"""Traces and packs notebook environments with ReproZip.
"""

__version__ = '1.0.14'


def _jupyter_nbextension_paths():
    return [
        dict(
            section='notebook',
            src='notebook-extension.js',
            dest='reprozip-jupyter.js',
            require='reprozip-jupyter',
        ),
    ]


def _jupyter_server_extension_paths():
    return [
        dict(module='reprozip_jupyter.server_extension'),
    ]
