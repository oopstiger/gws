import sys
import os
sys.path.append('../')

from lync import *


@WebApplication(root='/')
class StaticFile(object):
    def __init__(self, fsroot, mime_map):
        if not fsroot.endswith('/'):
            fsroot += '/'
        self.fsroot = fsroot
        self.mime_map = {
            'htm': 'text/html',
            'html': 'text/html',
            'css': 'text/css',
            'js': 'application/javascript',
            'jpg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'txt': 'text/plain'
        }
        for k, v in mime_map:
            self.mime_map[k] = v

    @WebApplicationHandler(strict=False)
    def get(self, context, **kwargs):
        fspath = self.fsroot[:-1] + context.request.plainpath
        res = context.response
        try:
            fsize = os.path.getsize(fspath)
            ext = os.path.splitext(fspath)[1][1:]
            ctype = self.mime_map.get(ext, 'application/octet-stream')
            res['Content-Type'] = ctype
            res['Content-Length'] = fsize
            context.output.write_response(res, data_part=False)
            with open(fspath, 'r') as file:
                d = file.read(4096)
                while d:
                    context.output.write(d)
                    d = file.read(4096)
            context.do_not_reply = True
        except Exception, e:
            context.response = HTTPResponse(404, 'Not Found')
            context.error = e
            context.keep_alive = False

