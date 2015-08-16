from lync import *
from apps.gws import GoogleSearch
from apps.fs import StaticFile


def log(tag, msg):
    print('[%s] [%s] %s' % (time.asctime(), tag, msg))


class console(object):
    debug = functools.partial(log, 'DEBUG')
    info = functools.partial(log, 'INFO')
    error = functools.partial(log, 'ERROR')


if __name__ == '__main__':
    conf = WebServerConfiguration()
    server = WebServer(logging=console, conf=conf)

    gws = GoogleSearch()
    fs = StaticFile('www/', {})
    server.install(gws, '/search')
    server.install(fs)
    server.run(('localhost', 8080))
