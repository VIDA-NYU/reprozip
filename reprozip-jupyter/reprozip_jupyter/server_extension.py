from notebook.utils import url_path_join as ujoin
import reprozip_jupyter
from rpaths import Path
import sys
from tornado.process import Subprocess
from tornado.web import RequestHandler


class TraceHandler(RequestHandler):
    def initialize(self, nbapp=None):
        self.nbapp = nbapp
        self._tempdir = None

    def post(self):
        self._filepath = Path(self.get_body_argument('file'))
        self.nbapp.log.info("Got request from client: file=%r", self._filepath)
        self._tempdir = Path.tempdir()
        proc = Subprocess(
            [sys.executable, '-c',
             'from reprozip_jupyter.main import main; main()',
             'trace',
             '-d', (self._tempdir / 'trace').path,
             self._filepath.path])
        proc.stdin.close()
        proc.set_exit_callback(self._trace_done)
        self.nbapp.log.info("Started tracing...")

    def _trace_done(self, returncode):
        self.nbapp.log.info("Tracing done, returned %d", returncode)
        if returncode == 0:
            # Pack
            proc = Subprocess(
                ['reprozip', 'pack', '-d',
                 (self._filepath / 'trace').path,
                 (self._filepath / 'experiment.rpz').path])
            proc.stdin.close()
            proc.set_exit_callback(self._packing_done)
            self.nbapp.log.info("Started packing...")
        else:
            self._tempdir.rmtree()
            self.send_error(500)

    def _packing_done(self, returncode):
        self.nbapp.log.info("Packing done, returned %d", returncode)
        if returncode == 0:
            # Send the file
            self.set_header('Content-Type', 'application/x-reprozip')
            self.set_header('Content-Disposition',
                            'attachment; filename="notebook.rpz"')
            with self._filepath.open('rb') as fp:
                chunk = fp.read(4096)
                self.write(chunk)
                while len(chunk) == 4096:
                    chunk = fp.read(4096)
                    self.write(chunk)
            self.finish()
            self.nbapp.log.info("File sent!")
        else:
            self.send_error(500)
        self._tempdir.rmtree()


def load_jupyter_server_extension(nbapp):
    nbapp.log.info('ReproZip extension loaded')

    webapp = nbapp.web_app
    base_url = webapp.settings['base_url']
    webapp.add_handlers(".*$", [
        (ujoin(base_url, r"/reprozip/trace"), TraceHandler, {'nbapp': nbapp}),
    ])
