import socket
import ssl
from urlparse import urlparse


class HTTPEOFError(Exception):
    def __init__(self, *args, **kwargs):
        Exception(self, args, kwargs)
        if len(args) > 0:
            self.message = str(args[0])

    def __str__(self):
        return self.message


class HTTPSocketError(Exception):
    def __init__(self, *args, **kwargs):
        Exception(self, args, kwargs)
        if len(args) > 0:
            self.message = str(args[0])

    def __str__(self):
        return self.message


class HTTPBadStreamError(Exception):
    def __init__(self, *args, **kwargs):
        Exception(self, args, kwargs)
        if len(args) > 0:
            self.message = str(args[0])

    def __str__(self):
        return self.message


class HTTPApplicationError(Exception):
    def __init__(self, *args, **kwargs):
        Exception(self, args, kwargs)
        if len(args) > 0:
            self.message = str(args[0])

    def __str__(self):
        return self.message


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
            d = self._sock.recv(1024)
        except:
            raise HTTPSocketError()
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

    def read_line(self):
        """ Read till a CRLF is encountered. The CRLF is not included in the returned string.
        :return: A string not including the CRLF.
        """
        while True:
            i = self._buf.find('\r\n')
            if i >= 0:
                line = self._buf[:i]
                self._buf = self._buf[i+2:]
                return line
            self._buf += self._recv()

    def read_chunk(self):
        """ Read a chunk from the HTTP stream.
          chunk      = chunk-size [ chunk-ext ] CRLF
                       chunk-data CRLF
          chunk-size = 1*HEXDIG
          last-chunk = 1*("0") [ chunk-ext ] CRLF
          chunk-data = 1*OCTET ; a sequence of chunk-size octets

         See RFC7230 for more information about 'chunked' encoding.
        :return:
        """
        chunk_size = int(self.read_line(), 16)
        if chunk_size == 0:
            return ''
        elif chunk_size < 0:
            raise HTTPBadStreamError('invalid chunk size.')
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

    def read_request(self, data_part=True):
        """ Extracts an HTTP request message from the stream.
        :param data_part: If data_part is set True, the entire message body will be load into the data field of
                          the returned HTTPRequest object. Otherwise, the message body is not extracted.
        :return: An HTTPRequest object.
        """
        req = HTTPRequest()
        line = self.read_line()
        req.method, req.path, req.version = self._parse_request_line(line)
        while True:
            line = self.read_line()
            if not line:
                break
            k, v = self._parse_header_line(line)
            req.headers.append(k, v)

        if data_part and req.method == 'POST':
            if 'Content-Length' in req:
                # explicit sized
                req.data = self.read(int(req['Content-Length']))
            elif req.headers.has('Transfer-Encoding', 'chunked') >= 0:
                # implied by 'chunked' encoding
                data = []
                chunk = self.read_chunk()
                while chunk:
                    data.append(chunk)
                req.data = ''.join(data)
                # trailers
                line = self.read_line()
                while line:
                    k, v = self._parse_header_line(line)
                    req.headers.append(k, v)
            else:
                raise HTTPBadStreamError('indeterminate request body size.')
        return req

    def read_response(self, data_part=True):
        """ Extracts an HTTP response message from the stream.
        :param data_part: If data_part is set True, the entire message body will be load into the data field of
                          the returned HTTPResponse object. Otherwise, the message body is not extracted.
        :return: An HTTPResponse object.
        """
        resp = HTTPResponse()
        line = self.read_line()
        resp.version, resp.status, resp.phrases = self._parse_status_line(line)
        while True:
            line = self.read_line()
            if not line:
                break
            k, v = self._parse_header_line(line)
            resp.headers.append(k, v)

        if data_part:
            if 'Content-Length' in resp:
                # explicit sized
                resp.data = self.read(int(resp['Content-Length']))
            elif resp.headers.has('Transfer-Encoding', 'chunked') >= 0:
                # implied by 'chunked' encoding
                data = []
                chunk = self.read_chunk()
                while chunk:
                    data.append(chunk)
                resp.data = ''.join(data)
                # trailers
                line = self.read_line()
                while line:
                    k, v = self._parse_header_line(line)
                    resp.headers.append(k, v)
            elif resp.headers.has('Connection', 'close') or resp.version == 'HTTP/1.0':
                # implied by EOF
                data = []
                try:
                    while True:
                        data.append(self.read_some(4096))
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
                raise HTTPSocketError('write to socket failed.')
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


def url_fetch_secure(url, keyfile, certfile, ca_certs, method='GET', headers=None, data=None, max_redirection=0):
    u = urlparse(url)
    port = u.port
    if u.scheme != 'http' and u.scheme != 'https':
        raise AssertionError('unsupported url scheme.')
    if not port:
        port = 443 if u.scheme == 'https' else 80
    conn = socket.create_connection((u.hostname, port))
    if u.scheme == 'https':
        conn = ssl.wrap_socket(conn, keyfile=keyfile, certfile=certfile, ca_certs=ca_certs)

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
    writer = HTTPStreamWriter(conn)
    writer.write_request(req)
    reader = HTTPStreamReader(conn)
    resp = reader.read_response(data_part=True)
    conn.shutdown(socket.SHUT_RDWR)
    conn.close()

    if max_redirection > 0 and 301 <= resp.status <= 302:
        if 'Location' not in resp:
            raise HTTPBadStreamError('bad redirection.')
        jmpurl = resp.headers['Location']
        return url_fetch_secure(jmpurl, keyfile, certfile, ca_certs, method, headers, data, max_redirection-1)
    return resp


def url_fetch(url, method='GET', headers=None, data=None, max_redirection=0):
    return url_fetch_secure(url, None, None, None, method, headers, data, max_redirection)


def html_escape(s):
    if not s:
        return ''
    return s.replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')


if __name__ == '__main__':
    r = url_fetch('http://www.baidu.com/')
    print(r)
