import json

from bs4 import BeautifulSoup
from libhttp import *

NCR_COOKIE = 'PREF=ID=1111111111111111:FF=0:LD=en:CR=2:TM=1439109218:LM=1439109218:V=1:S=v4gn7jZInBn-giuT'
RESULT_PAGE_HTML = ''


def shortcut(jumpurl):
    """ Extract the target URL from a google jump. """
    if isinstance(jumpurl, unicode):
        jumpurl = jumpurl.encode('utf-8')
    if jumpurl.startswith('/url?'):
        b = jumpurl.find('=')
        e = jumpurl.find('&')
        if e == -1:
            e = len(jumpurl)
        return url_decode(jumpurl[b+1:e])
    return jumpurl


def parse_result_element(node):
    """ Parses an HTML element that contains a search result item.
    :param node: The BeautifulSoup node object that holds the element.
    :return: A dict object contains extracted information.
    """
    r = {'title': None, 'url': None, 'site': None, 'st': None}
    a = node.find('a')
    if a:
        r['title'] = a.text.encode('utf-8')
        r['url'] = shortcut(a['href'])
    cite = node.find('cite')
    if cite:
        r['site'] = cite.text.encode('utf-8')
    st_span = node.find('span', class_='st')
    if st_span:
        r['st'] = st_span.text.encode('utf-8')
    return r


def parse_result_page(html):
    """ Parses an google search result page.
    :return: A dict object that contains extracted information.
    """
    soup = BeautifulSoup(html, 'html.parser')
    ires = soup.find('div', id='ires')
    ga = ires.find_all('li', class_='g')
    if not ga:
        ga = ires.find_all('div', class_='g')
    results = []
    for g in ga:
        results.append(parse_result_element(g))

    tb = soup.find('div', id='topabar')
    stat = tb.text.encode('utf-8') if tb else ''
    return {'stat': stat, 'results': results}


def gws_ncr_cookie():
    ncr = url_fetch('https://www.google.com/ncr')
    if ncr.status == 200:
        return ''   # domain for current region is google.com
    if 301 <= ncr.status <= 302:
        if ncr.headers.has('Location', 'https://www.google.com/') and 'Set-Cookie' in ncr:
            return ncr.headers['Set-Cookie'].split(';', 1)[0]
    return 'PREF=ID=1111111111111111:FF=0:LD=en:CR=2:TM=1439109218:LM=1439109218:V=1:S=v4gn7jZInBn-giuT'


def gws_search(words, page=1):
    gurl = 'https://www.google.com/search?q=%s&start=%d' % (url_encode(words), (page-1)*10)
    headers = HTTPHeaders()
    headers['Cookie'] = NCR_COOKIE
    headers['Refer'] = 'https://www.google.com/'
    resp = url_fetch(gurl, headers=headers)
    if resp.status != 200:
        return None

    ct = resp.headers.split('Content-Type')
    encoding = ct['charset'] if ct and 'charset' in ct else 'utf-8'
    return parse_result_page(resp.data.decode(encoding, 'ignore').encode('utf-8'))


def gws_result_page(html, kw, results):
    li = '<li><div><h3 class="t"><a href="%s" class="tl">%s</a></h3>' \
         '<cite class="c">%s</cite><br/>' \
         '<span class="st">%s</span></div></li>'
    ul = []
    for r in results['results']:
        if r['url'].find('://') < 0:
            # filter abnormal items
            continue
        ul.append(li % (r['url'], html_escape(r['title']), html_escape(r['site']), html_escape(r['st'])))
    ul = ''.join(ul)
    return html.replace('$STAT$', results['stat'])\
        .replace('$RESULTS$', ul).replace('$KEYWORDS$', html_escape(kw))


def gws_request_handler(req):
    queries = url_parse_queries(req.path)
    if not queries or not req.path.startswith('/api/search?') or 'q' not in queries:
        return HTTPResponse(404, 'Not Found', headers={'Content-Length': 0, 'Connection': 'close'})

    kws = queries['q']
    try:
        page = int(queries['p']) if 'p' in queries else 1
    except:
        page = 1
    results = gws_search(kws, page)
    if results is None:
        return HTTPResponse(400, 'Bad Request', headers={'Content-Length': 0, 'Connection': 'close'})
    else:
        # detect encoding
        html = gws_result_page(RESULT_PAGE_HTML, kws, results)
        return HTTPResponse(headers={'Content-Length': len(html),
                                     'Content-Type': 'text/html; charset=utf-8',
                                     'Connection': 'close'},
                            data=html)


def gws_server(address=('localhost', 80)):
    s = socket.socket()
    s.bind(address)
    s.listen(5)
    print('---- gws server is online now. ----')
    while True:
        c, a = s.accept()
        c.settimeout(3)
        try:
            reader = HTTPStreamReader(c)
            writer = HTTPStreamWriter(c)
            req = reader.read_request()
            queries = url_parse_queries(req.path)
            if not queries or not req.path.startswith('/api/search?') or 'q' not in queries:
                writer.write_response(HTTPResponse(404, 'Not Found',
                                                   headers={'Content-Length': 0, 'Connection': 'close'}))
                continue
            resp = gws_request_handler(req)
            writer.write_response(resp)
        except HTTPEOFError:
            pass
        except Exception, e:
            print('ERROR: %s' % str(e))
        finally:
            c.close()


if __name__ == '__main__':
    print('contacting google.com...')
    NCR_COOKIE = gws_ncr_cookie()
    print('loading html template...')
    with open('pages/gsl.htm') as t:
        RESULT_PAGE_HTML = t.read()
    gws_server()

