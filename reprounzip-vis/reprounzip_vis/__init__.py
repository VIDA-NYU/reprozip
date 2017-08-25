import argparse
import BaseHTTPServer
import SocketServer
import mimetypes
import shutil
import webbrowser

import pkg_resources

from reprounzip.unpackers.common import COMPAT_OK


__version__ = '0.1'


class VisHTTPHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    server_version = 'ReproUnzip/' + __version__

    def do_GET(self):
        print("Serving %s" % self.path)
        if self.path == '/provenance.json':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.wfile.write(self.provenance_json)
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
                shutil.copyfileobj(f, self.wfile)
                f.close()


def show_vis(args):
    # Extract JSON from package
    VisHTTPHandler.provenance_json = '{}'  # TODO

    # Serve static files and JSON document to browser
    port = 8003

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


def setup_vis(parser, **kwargs):
    """Visualizes the provenance of a package as a D3 graph in the browser.
    """
    parser.add_argument(
        'pack', nargs=argparse.OPTIONAL,
        help="Pack to visualize")
    parser.set_defaults(func=show_vis)

    return {'test_compatibility': COMPAT_OK}
