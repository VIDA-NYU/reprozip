from datetime import datetime
from notebook.utils import url_path_join as ujoin
from rpaths import Path
import subprocess
import sys
from tornado.process import Subprocess
from tornado.web import RequestHandler, asynchronous


try:
    unicode_ = unicode
except NameError:
    unicode_ = str


class TraceHandler(RequestHandler):
    def initialize(self, nbapp=None):
        self.nbapp = nbapp
        self._tempdir = None

    @asynchronous
    def post(self):
        self._notebook_file = Path(self.get_body_argument('file'))
        name = self._notebook_file.unicodename
        if name.endswith('.ipynb'):
            name = name[:-6]
        name = u'%s_%s.rpz' % (name, datetime.now().strftime('%Y%m%d-%H%M%S'))
        self._pack_file = self._notebook_file.parent / name
        self.nbapp.log.info("reprozip: tracing request from client: file=%r",
                            self._notebook_file)
        self._tempdir = Path.tempdir()
        self.nbapp.log.info("reprozip: created temp directory %r",
                            self._tempdir)
        proc = Subprocess(
            [sys.executable, '-c',
             'from reprozip_jupyter.main import main; main()',
             'trace',
             '--dont-save-notebook',
             '-d', self._tempdir.path,
             self._notebook_file.path],
            stdin=subprocess.PIPE)
        proc.stdin.close()
        proc.set_exit_callback(self._trace_done)
        self.nbapp.log.info("reprozip: started tracing...")

    def _trace_done(self, returncode):
        self.nbapp.log.info("reprozip: tracing done, returned %d", returncode)
        if returncode == 0:
            # Pack
            if self._pack_file.exists():
                self._pack_file.remove()
            proc = Subprocess(
                ['reprozip', 'pack', '-d',
                 self._tempdir.path,
                 self._pack_file.path],
                stdin=subprocess.PIPE)
            proc.stdin.close()
            proc.set_exit_callback(self._packing_done)
            self.nbapp.log.info("reprozip: started packing...")
        else:
            self._tempdir.rmtree()
            if returncode == 3:
                self.set_header('Content-Type', 'application/json')
                self.finish(
                    {'error': "There was an error running the notebook. "
                              "Please make sure that it can run from top to "
                              "bottom without error before packing."})
            else:
                self.send_error(500)

    def _packing_done(self, returncode):
        self.nbapp.log.info("reprozip: packing done, returned %d", returncode)
        if returncode == 0:
            # Send the response
            self.set_header('Content-Type', 'application/json')
            self.finish({'bundle': unicode_(self._pack_file)})
            self.nbapp.log.info("reprozip: response sent!")
        else:
            self.send_error(500)
        self._tempdir.rmtree()


def load_jupyter_server_extension(nbapp):
    nbapp.log.info('reprozip: notebook extension loaded')

    webapp = nbapp.web_app
    base_url = webapp.settings['base_url']
    webapp.add_handlers(".*$", [
        (ujoin(base_url, r"/reprozip/trace"), TraceHandler, {'nbapp': nbapp}),
    ])
