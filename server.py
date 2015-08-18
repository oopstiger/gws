from lync import *
from apps.gws import GoogleSearch
from apps.fs import StaticFile
import json


def log(tag, msg):
    print('[%s] [%s] %s' % (time.asctime(), tag, msg))


class console(object):
    debug = functools.partial(log, 'DEBUG')
    info = functools.partial(log, 'INFO')
    warn = functools.partial(log, 'WARN')
    error = functools.partial(log, 'ERROR')


if __name__ == '__main__':
    try:
        with open('server.json') as f:
            conf = json.load(f, 'utf-8')
    except:
        conf = WebServerConfiguration()
        console.warn('file server.json is not found, using default configurations.')

    server = WebServer(logging=console, conf=conf)
    gws = GoogleSearch('www.google.com.hk')
    fs = StaticFile('www/', {})
    server.install(gws, '/search')
    server.install(fs)
    server.run()
