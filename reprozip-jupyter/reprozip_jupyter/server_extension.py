from notebook.utils import url_path_join as ujoin
from tornado.web import RequestHandler


class TraceHandler(RequestHandler):
    def initialize(self, nbapp=None):
        self.nbapp = nbapp

    def post(self):
        filepath = self.get_body_argument('file')
        self.nbapp.log.info("Got request from client: file=%r", filepath)
        self.finish()


def load_jupyter_server_extension(nbapp):
    nbapp.log.info('ReproZip extension loaded')

    webapp = nbapp.web_app
    base_url = webapp.settings['base_url']
    webapp.add_handlers(".*$", [
        (ujoin(base_url, r"/reprozip/trace"), TraceHandler, {'nbapp': nbapp}),
    ])
