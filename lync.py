import sys
import traceback
import socket
import ssl
import time
import urlparse
import re
import functools
import threading


__VERSION__ = '0.1'


def url_encode(s, encoding='utf-8'):
    """ Encode s with percentage-encoding. """
    eb = bytearray()
    for b in bytearray(s.encode(encoding)):
        if b >= 126 or not (97 <= b <= 122 or 65 <= b <= 90 or 48 <= b <= 57 or 45 <= b <= 46 or b == 95):
            eb.extend("%%%02x" % b)
        else:
            eb.append(b)
    return str(eb)


def url_decode(s):
    """ Decode a string in percentage-encoding. """
    original = bytearray()
    pos = 0
    eb = bytearray(s, encoding='utf-8')
    eblen = len(eb)
    while pos < eblen:
        b = eb[pos]
        if b == 37:    # ASCII code of '%' is 37
            original.append(int(s[pos+1:pos+3], 16))
            pos += 2
        elif b == 43:  # ASCII code of '+' is 43
            original.append(' ')
        else:
            original.append(b)
        pos += 1
    return str(original)


def url_parse_queries(url):
    queries = {}
    try:
        for q in url.split('?', 1)[1].split('#', 1)[0].split('&'):
            kv = q.split('=', 1)
            queries[kv[0].strip()] = url_decode(kv[1].strip()) if len(kv) > 1 else ''
    except:
        pass
    return queries


def url_fetch_secure(url, keyfile, certfile, ca_certs, method='GET', headers=None, data=None,
                     max_redirection=0, limit=10485760):
    u = urlparse.urlparse(url)
    port = u.port
    if u.scheme != 'http' and u.scheme != 'https':
        raise AssertionError('unsupported url scheme.')
    if not port:
        port = 443 if u.scheme == 'https' else 80

    req = HTTPRequest(method=method, path=url[len(u.scheme)+3+len(u.netloc):])
    if method == 'POST' and data:
        req.data = data
    if headers:
        req.headers = headers
    if req.data:
        req.headers['Content-Length'] = len(req.data)
    if 'Host' not in req:
        # Make 'Host' the first header.
        req.headers.insert(0, 'Host', u.netloc)
    req['Connection'] = 'close'
    if 'User-Agent' not in req:
        req['User-Agent'] = 'AppleWebKit/537.36'

    conn = socket.create_connection((u.hostname, port))
    if u.scheme == 'https':
        conn = ssl.wrap_socket(conn, keyfile=keyfile, certfile=certfile, ca_certs=ca_certs)
    writer = HTTPStreamWriter(conn)
    writer.write_request(req)
    reader = HTTPStreamReader(conn)
    resp = reader.read_response(data_part=True, limit=limit)
    conn.close()

    if max_redirection > 0 and 301 <= resp.status <= 302:
        if 'Location' not in resp:
            raise HTTPBadStreamError('bad redirection.')
        jmpurl = resp.headers['Location']
        return url_fetch_secure(jmpurl, keyfile, certfile, ca_certs, method, headers, data, max_redirection-1, limit)
    return resp


def url_fetch(url, method='GET', headers=None, data=None, max_redirection=0, limit=10485760):
    return url_fetch_secure(url, None, None, None, method, headers, data, max_redirection, limit)


def html_escape(s):
    if not s:
        return ''
    return s.replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')


class HTTPEOFError(Exception):
    def __init__(self, *args, **kwargs):
        super(HTTPEOFError, self).__init__(args, kwargs)


class HTTPNetworkError(Exception):
    def __init__(self, *args, **kwargs):
        super(HTTPNetworkError, self).__init__(args, kwargs)


class HTTPBadStreamError(Exception):
    def __init__(self, *args, **kwargs):
        super(HTTPBadStreamError, self).__init__(args, kwargs)


class HTTPSizeTooLargeError(Exception):
    def __init__(self, *args, **kwargs):
        super(HTTPSizeTooLargeError, self).__init__(args, kwargs)


class HTTPHeaders(object):
    def __init__(self):
        self._items = []

    def __contains__(self, item):
        return self.find(item) != -1

    def __setitem__(self, key, value):
        value = str(value)
        i = self.find(key)
        if i < 0:
            self.append(key, value)
        self._items[i] = (key, value)

    def __getitem__(self, item):
        i = self.find(item)
        if i < 0:
            raise IndexError(str(item) + ' not found')
        return self._items[i][1]

    def __len__(self):
        return len(self._items)

    def __str__(self):
        s = ['{']
        for kv in self._items:
            s.append('\'%s\': \'%s\', ' % (str(kv[0]), str(kv[1])))
        if self._items:
            s[len(self._items)] = s[len(self._items)][:-2]   # remove last colon and space
        s.append('}')
        return ''.join(s)

    def get(self, key, default=None):
        i = self.find(key)
        return self.at(i) if i >= 0 else default

    def at(self, i):
        return self._items[i][1]

    def items(self):
        return self._items

    def insert(self, i, k, v):
        self._items.insert(i, (k, str(v)))

    def append(self, k, v):
        self._items.append((k, str(v)))

    def pop(self, i=-1):
        self._items.pop(i)

    def remove(self, key):
        i = self.find(key)
        while i >= 0:
            self.pop(i)
            i = self.find(key, i)

    def find(self, key, start=0):
        end = len(self._items)
        if start < end:
            key = key.lower()
            for i in range(start, end):
                if self._items[i][0].lower() == key:
                    return i
        return -1

    def find_all(self, key, start=0):
        lv = []
        end = len(self._items)
        if start < end:
            key = key.lower()
            for i in range(start, end):
                if self._items[i][0].lower() == key:
                    lv.append(self._items[i][1])
        return lv

    def has(self, key, value, start=0):
        value = str(value)
        for i in range(start, len(self._items)):
            if self._items[i] == (key, value):
                return i
        return -1

    def split(self, key, col=';', eq='=', spaces=' '):
        """ Splits a header value.
        :param key: Name of the header field to be split.
        :param col: column separator
        :param eq: name/value separator within a column
        :param spaces: white space characters that will be stripped.
        :return: A dict object.
        """
        i = self.find(key)
        if i < 0:
            return None
        values = {}
        for p in self._items[i][1].split(col):
            kv = p.strip(spaces).split(eq, 1)
            values[kv[0]] = kv[1] if len(kv) > 1 else ''
        return values

    @property
    def content_length(self):
        length = self.get('Content-Length')
        return int(length) if length else None

    @property
    def content_type(self):
        """ Get Content-Type void of parameters. """
        ct = self.get('Content-Type')
        if ct:
            return ct.split(';', 1)[0].strip()
        return ''

    @property
    def charset(self):
        params = self.split('Content-Type')
        return params.get('charset', '')


class HTTPRequest(object):
    def __init__(self, method='GET', path='/', version='HTTP/1.1', headers=None, data=''):
        self.method = method
        self.path = path
        self.version = version
        self.headers = HTTPHeaders()
        if headers:
            for k, v in headers.items():
                self.headers.append(k, v)
        self.data = data

    def __str__(self):
        self.format(data_part=True)

    def __contains__(self, key):
        return self.headers.__contains__(key)

    def __getitem__(self, key):
        return self.headers.__getitem__(key)

    def __setitem__(self, key, value):
        return self.headers.__setitem__(key, value)

    @property
    def startline(self):
        return '%s %s %s' % (self.method, self.path, self.version)

    @property
    def plainpath(self):
        q = self.path.find('?')
        return url_decode(self.path if q < 0 else self.path[:q])

    def format(self, data_part=True):
        parts = ['%s %s %s\r\n' % (self.method, self.path, self.version)]
        for k, v in self.headers.items():
            parts.append(k + ': ' + str(v) + '\r\n')
        parts.append('\r\n')
        if data_part:
            parts.append(self.data)
        return ''.join(parts)


class HTTPResponse(object):
    def __init__(self, status=200, phrases='OK', version='HTTP/1.1', headers=None, data=''):
        self.status = status
        self.phrases = phrases
        self.version = version
        self.headers = HTTPHeaders()
        if headers:
            for k, v in headers.items():
                self.headers.append(k, str(v))
        self.data = data

    def __str__(self):
        return self.format(data_part=True)

    def __contains__(self, key):
        return self.headers.__contains__(key)

    def __getitem__(self, key):
        return self.headers.__getitem__(key)

    def __setitem__(self, key, value):
        return self.headers.__setitem__(key, value)

    @property
    def statusline(self):
        return '%s %d %s' % (self.version, self.status, self.phrases)

    def format(self, data_part=True):
        parts = ['%s %d %s\r\n' % (self.version, self.status, self.phrases)]
        for k, v in self.headers.items():
            parts.append(k + ': ' + str(v) + '\r\n')
        parts.append('\r\n')
        if data_part:
            parts.append(self.data)
        return ''.join(parts)


class HTTPStreamReader(object):
    def __init__(self, sock):
        self._sock = sock
        self._buf = ''

    def _recv(self):
        try:
            d = self._sock.recv(16384)
        except:
            raise HTTPNetworkError()
        if not d:
            raise HTTPEOFError('connection has been closed.')
        return d

    def read(self, count):
        """ Read count bytes from the HTTP stream.
        :param count: Number of bytes to read.
        :return: A string, length of which is exactly count.
        """
        while len(self._buf) < count:
            self._buf += self._recv()
        d = self._buf[:count]
        self._buf = self._buf[count:]
        return d

    def read_some(self, max_count):
        """ Read up to max_count bytes from the HTTP stream.
        :param max_count: Maximum number of bytes to read.
        :return: A string, length of which ranges from 1 to max_count.
        """
        if not self._buf:
            self._buf = self._recv()
        q = min(max_count, len(self._buf))
        d = self._buf[:q]
        self._buf = self._buf[q:]
        return d

    def read_line(self, le='\r\n', limit=16384):
        """ Read till a line ending sequence is encountered.
         The line ending sequence is not included in the returned string.
         This method raises an HTTPSizeTooLargeError when the length of the line exceeds the limit.
        :param le: Line ending sequence, defaults to '\r\n'
        :param limit: Maximum number of octets allowed.
        :return: A string not including the line ending sequence.
        """
        while True:
            i = self._buf.find(le)
            if i >= 0:
                line = self._buf[:i]
                self._buf = self._buf[i+2:]
                return line
            else:
                if len(self._buf) >= limit:
                    raise HTTPSizeTooLargeError('line too long.')
            self._buf += self._recv()

    def read_chunk(self, limit=10485760):
        """ Read a chunk from the HTTP stream.
         This method raises an HTTPSizeTooLargeError when the length of the line exceeds the limit.
         :param limit: Maximum number of octets allowed.
         :return: A string that containing the chunk data.
        """
        # See RFC7230 for more information about 'chunked' encoding.
        #  chunk      = chunk-size [ chunk-ext ] CRLF
        #               chunk-data CRLF
        #  chunk-size = 1*HEXDIG
        #  last-chunk = 1*("0") [ chunk-ext ] CRLF
        #  chunk-data = 1*OCTET ; a sequence of chunk-size octets
        try:
            chunk_size = int(self.read_line(limit=10), 16)
        except ValueError:
            raise HTTPBadStreamError('invalid chunk head.')
        if chunk_size == 0:
            return ''
        elif chunk_size < 0:
            raise HTTPBadStreamError('negative chunk size.')
        elif chunk_size > limit:
            raise HTTPSizeTooLargeError('chunk too large.')
        chunk = self.read(chunk_size)
        if '\r\n' != self.read(2):
            raise HTTPBadStreamError('invalid chunk ending.')
        return chunk

    @staticmethod
    def _parse_status_line(l):
        parts = l.split(' ', 2)
        try:
            ver = parts[0].strip()
            code = int(parts[1].strip())
            phr = parts[2].strip()
            return ver, code, phr
        except:
            raise HTTPBadStreamError('bad status line.')

    @staticmethod
    def _parse_request_line(l):
        parts = l.split(' ', 2)
        try:
            method = parts[0].strip()
            path = parts[1].strip()
            ver = parts[2].strip()
            return method, path, ver
        except:
            raise HTTPBadStreamError('bad request line.')

    @staticmethod
    def _parse_header_line(l):
        parts = l.split(':', 1)
        try:
            key = parts[0].strip()
            value = parts[1].strip()
            return key, value
        except:
            raise HTTPBadStreamError('bad header line.')

    def read_request(self, data_part=True, limit=65536):
        """ Extracts an HTTP request message from the stream.
        :param data_part: If data_part is set True, the entire message body will be load into the data field of
                          the returned HTTPRequest object. Otherwise, the message body is not extracted.
        :param limit: Maximum number of octets allowed.
        :return: An HTTPRequest object.
        """
        req = HTTPRequest()
        line = self.read_line(limit=limit)
        req.method, req.path, req.version = self._parse_request_line(line)
        while True:
            limit -= len(line) + 2
            line = self.read_line(limit=limit)
            if not line:
                break
            k, v = self._parse_header_line(line)
            req.headers.append(k, v)

        if data_part and req.method == 'POST':
            if 'Content-Length' in req:
                # explicit sized
                length = int(req['Content-Length'])
                if length > limit:
                    raise HTTPSizeTooLargeError('entity size too large.')
                req.data = self.read(length)
                limit -= length
            elif req.headers.has('Transfer-Encoding', 'chunked') >= 0:
                # implied by 'chunked' encoding
                data = []
                chunk = self.read_chunk(limit=limit)
                while chunk:
                    limit -= len(chunk) + 2
                    data.append(chunk)
                req.data = ''.join(data)
                # trailers
                line = self.read_line(limit=limit)
                while line:
                    k, v = self._parse_header_line(line)
                    req.headers.append(k, v)
            else:
                raise HTTPBadStreamError('indeterminate request body size.')
        return req

    def read_response(self, data_part=True, limit=65536):
        """ Extracts an HTTP response message from the stream.
        :param data_part: If data_part is set True, the entire message body will be load into the data field of
                          the returned HTTPResponse object. Otherwise, the message body is not extracted.
        :param limit: Maximum number of octets allowed.
        :return: An HTTPResponse object.
        """
        resp = HTTPResponse()
        line = self.read_line(limit=limit)
        resp.version, resp.status, resp.phrases = self._parse_status_line(line)
        while True:
            limit -= len(line) + 2
            line = self.read_line(limit=limit)
            if not line:
                break
            k, v = self._parse_header_line(line)
            resp.headers.append(k, v)

        if data_part:
            if 'Content-Length' in resp:
                # explicit sized
                length = int(resp['Content-Length'])
                if length > limit:
                    raise HTTPSizeTooLargeError('entity size too large.')
                resp.data = self.read(length)
                limit -= length
            elif resp.headers.has('Transfer-Encoding', 'chunked') >= 0:
                # implied by 'chunked' encoding
                data = []
                chunk = self.read_chunk(limit=limit)
                while chunk:
                    limit -= len(chunk) + 2
                    data.append(chunk)
                resp.data = ''.join(data)
                # trailers
                line = self.read_line(limit=limit)
                limit -= len(line) + 2
                while line:
                    k, v = self._parse_header_line(line)
                    resp.headers.append(k, v)
            elif resp.headers.has('Connection', 'close') or resp.version == 'HTTP/1.0':
                # implied by EOF
                data = []
                try:
                    while True:
                        data.append(self.read_some(limit))
                        limit -= len(data[-1])
                except HTTPEOFError:
                    pass
                resp.data = ''.join(data)
            else:
                raise HTTPBadStreamError('indeterminate response body size.')
        return resp


class HTTPStreamWriter(object):
    def __init__(self, sock):
        self._sock = sock

    def write(self, data):
        while data:
            n = self._sock.send(data)
            if n < 1:
                raise HTTPNetworkError('write to socket failed.')
            data = data[n:]

    def write_line(self, data):
        self.write(data)
        self.write('\r\n')

    def write_chunk(self, chunk):
        self.write('%x\r\n' % len(chunk))
        self.write(chunk)
        self.write('\r\n')

    def write_request(self, req, data_part=True):
        self.write(req.format(data_part=False))
        if data_part:
            self.write(req.data)

    def write_response(self, resp, data_part=True):
        self.write(resp.format(data_part=False))
        if data_part:
            self.write(resp.data)


class HTTPGenericError(Exception, HTTPResponse):
    def __init__(self, status=200, phrases='OK'):
        Exception.__init__(self)
        HTTPResponse.__init__(self, status, phrases)


class HTTPMovedPermanently(HTTPGenericError):
    def __init__(self, location):
        super(HTTPMovedPermanently, self).__init__(301, 'Moved Permanently')
        self.headers.append('Location', location)


class HTTPMovedTemporarily(HTTPGenericError):
    def __init__(self, location):
        super(HTTPMovedTemporarily, self).__init__(302, 'Found')
        self.headers.append('Location', location)


class HTTPBadRequest(HTTPGenericError):
    def __init__(self):
        super(HTTPBadRequest, self).__init__(400, 'Bad Request')


class HTTPNotFound(HTTPGenericError):
    def __init__(self):
        super(HTTPNotFound, self).__init__(404, 'Not Found')


class HTTPServerError(HTTPGenericError):
    def __init__(self):
        super(HTTPServerError, self).__init__(500, 'Server Error')


class HTTPBadGateway(HTTPGenericError):
    def __init__(self):
        super(HTTPBadGateway, self).__init__(502, 'Bad Gateway')


class WebSessionContext(object):
    def __init__(self, sock):
        self.input = HTTPStreamReader(sock)
        self.output = HTTPStreamWriter(sock)
        self.request = None
        self.response = None
        self.error = None

        # Number of requests received from current connection.
        # The web server increases this counter automatically, web applications may
        # not modify this field.
        self.request_count = 0

        # Application specific data. This field is valid along with the connection.
        self.data = None

        # If do_not_reply is set True, the web server will not send the response
        # message to the client. In case the response message has been sent within
        # the request handler, this flag should be set to True.
        # ***This field is reset per request.***
        self.do_not_reply = False

        # If do_not_modify is set True, the web server will forward the response
        # message to the client without any modification. By default, the web
        # server checks the response message for missing headers and adds extra
        # fields to the message, like 'Content-Type', 'Content-Length', etc., before
        # sending it to the client.
        # ***This field is reset per request.***
        self.do_not_modify = False

        # keep_alive indicates whether the connection should be kept alive.
        # If keep_alive is set to False, the web server will close the connection
        # immediately after the response message is sent.
        self.keep_alive = True

        # switch_protocol indicates whether the connection has been taken over by
        # other protocols. If switch_protocol is set to True, the web server will
        # not operate the connection any further, thus it's the web application's
        # obligation to manage the connection.
        # A typical scenario of using this field is handling a CONNECT request.
        self.switch_protocol = False

    def update(self, request):
        self.do_not_modify = False
        self.do_not_reply = False
        self.error = None
        self.request = request
        self.response = HTTPResponse(200, 'OK')
        self.request_count += 1


class WebApplication(object):
    """ Decorates a class to make it a web application. """
    def __init__(self, root='/', host='*'):
        if not root.endswith('/'):
            root += '/'
        self.root = root
        self.host = host
        self.entries = {}

    def __call__(self, klass):
        """ When WebApplication object is used as decorator, this method will be called.
        :param klass: The class to be decorated.
        :return: The decorated class.
        """
        klass.webapp = WebApplication(root=self.root, host=self.host)
        for name, handler in klass.__dict__.items():
            if type(handler) == WebApplicationHandler:
                handler.name = name
                klass.webapp.register(handler)
        return klass

    def register(self, handler):
        """ Registers a handler
        :param handler: WebApplicationHandler object, the handler to be registered.
        """
        self.entries[handler.path] = handler

    def map(self, context):
        """ Maps a request to a handler.
        :param context: The session context.
        :return: The name of the handler, a string.
        """
        req = context.request
        # Remove heading app path
        handler_path = req.path[len(self.root)-1:]

        # For relative paths, the query part and fragment part should be removed
        if req.path[0] == '/':
            q = handler_path.find('?')
            if q >= 0:
                handler_path = handler_path[:q]

        for handler in self.entries.values():
            if req.method == handler.method:
                # Use naive string compare in strict mode, in this case handler.pathre is None
                if (handler.pathre is None and handler.path == handler_path) or\
                        (handler.pathre and handler.pathre.match(handler_path)):
                    return handler
        return None


class WebApplicationHandler(object):
    """ Decorates a method to make it a request handler.  """
    def __init__(self, func=None, pattern='/', strict=True, method='GET'):
        """
        :param func: Name of the handler method.
        :param pattern: Pattern of paths that the handler bounds to.
        :param strict: Use strict matching mode or not.
        :param method: HTTP method that the handler accepts.
        """
        self.path = pattern
        self.pathre = re.compile(pattern) if not strict else None
        self.name = ''
        self.func = func
        self.method = method

    def __get__(self, instance, owner):
        """ This method is called when WebApplicationHandler is used as a descriptor. """
        return functools.partial(self.func, instance)

    def __call__(self, func):
        """ This method is called when a descriptor is required. """
        return WebApplicationHandler(func, self.path, self.pathre is None, self.method)


def WebServerConfiguration():
    """ Generates a default WebServer configuration.
    :return: a dict object.
    """
    conf = {
        WebServer.CONF_SERVER_LISTEN: 'localhost:8080',
        WebServer.CONF_THREAD_POOL_SIZE: 4,
        WebServer.CONF_SERVER_NAME: 'lync',
        WebServer.CONF_DEFAULT_CONTENT_TYPE: 'text/html; charset=utf-8',
        WebServer.CONF_CONNECTION_TIMEOUT: 3000,
        WebServer.CONF_MAX_KEEP_ALIVE: 0,
        WebServer.CONF_MAX_MESSAGE_SIZE: 65536,
        WebServer.CONF_HIDE_EXCEPT_INFO: True
        }
    return conf


class WebServer(object):
    """ Container for web applications. """

    # configuration keys
    CONF_SERVER_LISTEN = 'server.listen'
    CONF_THREAD_POOL_SIZE = 'server.thread-pool-size'
    CONF_SERVER_NAME = 'server.name'
    CONF_DEFAULT_CONTENT_TYPE = 'server.default-content-type'
    CONF_CONNECTION_TIMEOUT = 'server.connection-timeout'
    CONF_MAX_KEEP_ALIVE = 'server.max-keep-alive'
    CONF_MAX_MESSAGE_SIZE = 'server.max-message-size'
    CONF_HIDE_EXCEPT_INFO = 'server.hide-except-info'

    def __init__(self, logging, conf=None):
        self.logging = logging
        self.conf = conf if conf else WebServerConfiguration()
        self._apps = []
        self._acceptor = None
        self._acceptor_guard = threading.Event()

    def install(self, app, root=None):
        """ Installs a web application.
        :param app: Web application object.
        :param root: Path that the application should be installed to.
        """
        if root:
            app.webapp.root = root if root.endswith('/') else root + '/'
        self._apps.append((app.webapp.root, app))
        self.logging.info('web application installed: ' + app.webapp.root)

    def remove(self, root):
        """ Removes a web application.
        :param root: Root path of the application to be removed.
        """
        if not root.endswith('/'):
            root += '/'
        for i in range(0, len(self._apps)):
            if self._apps[i][0] == root:
                self._apps.pop(i)
                self.logging.info('web application removed: ' + root)
                return True
        return False

    def run(self):
        ap = self.conf[WebServer.CONF_SERVER_LISTEN].strip().split(':', 1)
        address = (ap[0], int(ap[1]) if len(ap) == 2 else 80)
        self.logging.info('launching web server %s:%d ...' % address)
        try:
            acceptor = socket.socket()
            acceptor.bind(address)
            acceptor.listen(4)
        except Exception, e:
            self.logging.error('ACCESS DENIED!!! web server can not start.')
            self.logging.error(str(e))
            return
        self._acceptor = acceptor
        self._acceptor_guard.set()

        threads = []
        for i in range(0, self.conf[WebServer.CONF_THREAD_POOL_SIZE]):
            threads.append(threading.Thread(target=self._server_thread))
            threads[i].start()
        self.logging.info('---- web server is online now. ----')
        for th in threads:
            th.join()

    def _map(self, context):
        """ Find the app that is capable of handling the request.
        :return: An (app, handler) tuple.
        """
        req = context.request
        host = req.headers.get('Host')
        for path, app in self._apps:
            if (app.webapp.host == '*' or app.webapp.host == host) and req.path.startswith(path):
                return app, app.webapp.map(context)
        return None, None

    def _server_thread(self):
        while True:
            self._acceptor_guard.wait()
            client, addr = self._acceptor.accept()
            client.settimeout(self.conf[WebServer.CONF_CONNECTION_TIMEOUT])
            self._acceptor_guard.set()

            max_msg_size = self.conf[WebServer.CONF_MAX_MESSAGE_SIZE]
            max_keep_alive = self.conf[WebServer.CONF_MAX_KEEP_ALIVE]
            context = WebSessionContext(client)
            while True:
                try:
                    context.update(context.input.read_request(limit=max_msg_size))
                    context.keep_alive = max_keep_alive == 0 or max_keep_alive > context.request_count
                    req, res = context.request, context.response
                    app, handler = self._map(context)
                    if not handler:
                        self.logging.info('handler not found for: ' + req.startline)
                        context.response = HTTPNotFound()
                    else:
                        try:
                            queries = url_parse_queries(req.path)
                            handler.func(app, context, **queries)
                        except HTTPGenericError as e:
                            context.response = e
                        except Exception as e:
                            context.keep_alive = False
                            context.response = HTTPServerError()
                            stacktrace = traceback.format_exc().encode('utf-8', 'ignore')
                            self.logging.error(str(e))
                            self.logging.error(traceback.format_exc().encode('utf-8', 'ignore'))
                            if not self.conf[WebServer.CONF_HIDE_EXCEPT_INFO]:
                                context.response.data = stacktrace
                                context.response['Content-Type'] = 'text/plain; charset=utf-8'
                    if not context.do_not_reply:
                        self._reply(context)
                        self.logging.info('%d %s' % (context.response.status, req.startline))
                except HTTPSizeTooLargeError as e:
                    context.output.write_response(HTTPBadRequest())
                    context.error = e
                    context.keep_alive = False
                except Exception as e:
                    context.error = e
                    context.keep_alive = False

                if not context.keep_alive:
                    try:
                        client.close()
                    except Exception, e:
                        self.logging.error('error close connection: ' + str(e))
                    break  # end this session
                if context.switch_protocol:
                    # The connection has been taken over by other protocols.
                    # It's other protocols' obligation to close the connection when the
                    # connection is no longer used.
                    self.logging.info('protocol switched %s:%d.' % (addr[0], addr[1]))
                    break

    def _reply(self, context):
        req, res = context.request, context.response
        if context.do_not_modify:
            context.output.write_response(res)
            return

        server = self.conf.get(WebServer.CONF_SERVER_NAME, '')
        if server:
            res['Server'] = server
        if res.status == 200 and req.method in ['GET', 'HEAD', 'POST']:
            res['Date'] = time.asctime() + ' ' + time.tzname[0]
        if res.data:
            res['Content-Length'] = len(res.data)
            if 'Content-Type' not in res:
                res['Content-Type'] = self.conf[WebServer.CONF_DEFAULT_CONTENT_TYPE]
        else:
            if req.method in ['GET', 'POST'] and 'Content-Length' not in res:
                res['Content-Length'] = 0
        if not context.keep_alive:
            res['Connection'] = 'close'
        context.output.write_response(res)


if __name__ == '__main__':
    r = url_fetch('http://example.com/')
    print(r)
