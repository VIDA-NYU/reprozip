import argparse
import BaseHTTPServer
import SocketServer
import mimetypes
import os
import pkg_resources
from rpaths import Path
import shutil
import tempfile
import webbrowser

from reprounzip.common import RPZPack
from reprounzip.unpackers.common import COMPAT_OK
from reprounzip.unpackers.graph import generate

__version__ = '0.1'


class VisHTTPHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    server_version = 'ReproUnzip/' + __version__

    def do_GET(self):
        print("Serving %s" % self.path)
        if self.path == '/provenance.json':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            with open(self.provenance_json, 'rb') as f:
                shutil.copyfileobj(f, self.wfile)
        else:
            try:
                f = pkg_resources.resource_stream('reprounzip_vis',
                                                  'static/' + self.path)
            except IOError:
                self.send_response(404)
            else:
                self.send_response(200)
                if self.path == '/':
                    ctype = 'text/html'
                else:
                    ctype = mimetypes.guess_type(self.path)[0]
                self.send_header('Content-Type', ctype)
                self.end_headers()
                shutil.copyfileobj(f, self.wfile)
                f.close()


def show_vis(args):
    # Extract JSON from package
    fd, json_file = tempfile.mkstemp(prefix='reprounzip_vis_', suffix='.json')
    try:
        rpz_pack = RPZPack(args.pack)
        with rpz_pack.with_config() as config:
            with rpz_pack.with_trace() as trace:
                generate(Path(json_file), config, trace, graph_format='json')
        os.close(fd)

        VisHTTPHandler.provenance_json = json_file

        # Serve static files and JSON document to browser
        port = 8002

        httpd = SocketServer.TCPServer(('', port), VisHTTPHandler)
        print("serving at port %d" % port)

        # Open web browser
        webbrowser.open('http://localhost:%d/index.html' % port)

        # Serve until killed
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
    finally:
        os.remove(json_file)


def setup_vis(parser, **kwargs):
    """Visualizes the provenance of a package as a D3 graph in the browser.
    """
    parser.add_argument(
        'pack', nargs=argparse.OPTIONAL,
        help="Pack to visualize")
    parser.set_defaults(func=show_vis)

    return {'test_compatibility': COMPAT_OK}
