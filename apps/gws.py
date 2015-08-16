import sys
sys.path.append('../')

from lync import *
from bs4 import BeautifulSoup


@WebApplication()
class GoogleSearch(object):
    def __init__(self):
        self.ncr_cookie = self.gws_ncr_cookie()

    @staticmethod
    def shortcut(url):
        """ Extract the target URL from a google jump. """
        jumpurl = url.encode('utf-8') if isinstance(url, unicode) else url
        if jumpurl.startswith('/url?'):
            b = jumpurl.find('=')
            e = jumpurl.find('&')
            if e == -1:
                e = len(jumpurl)
            return url_decode(jumpurl[b+1:e])
        return jumpurl

    def parse_result_element(self, node):
        """ Parses an HTML element that contains a search result item.
        :param node: The BeautifulSoup node object that holds the element.
        :return: A dict object contains extracted information.
        """
        r = {'title': None, 'url': None, 'site': None, 'st': None}
        a = node.find('a')
        if a:
            r['title'] = a.text.encode('utf-8')
            r['url'] = self.shortcut(a['href'])
        cite = node.find('cite')
        if cite:
            r['site'] = cite.text.encode('utf-8')
        st_span = node.find('span', class_='st')
        if st_span:
            r['st'] = st_span.text.encode('utf-8')
        return r

    @staticmethod
    def gws_ncr_cookie():
        #try:
        #    ncr = url_fetch('https://www.google.com/ncr')
        #    if ncr.status == 200:
        #        return ''   # domain for current region is google.com
        #    if 301 <= ncr.status <= 302:
        #        if ncr.headers.has('Location', 'https://www.google.com/') and 'Set-Cookie' in ncr:
        #            return ncr.headers['Set-Cookie'].split(';', 1)[0]
        #except:
        #    pass
        return 'PREF=ID=1111111111111111:FF=0:LD=en:CR=2:TM=1439109218:LM=1439109218:V=1:S=v4gn7jZInBn-giuT'

    @WebApplicationHandler('/json')
    def search(self, context, w, p=1, **kwargs):
        try:
            p = int(p)
        except ValueError:
            p = 1
        gurl = 'https://www.google.com/search?q=%s&start=%d' % (url_encode(w), (p-1)*10)
        headers = HTTPHeaders()
        headers['Cookie'] = self.ncr_cookie
        headers['Refer'] = 'https://www.google.com/'
        resp = url_fetch(gurl, headers=headers)
        if resp.status != 200:
            raise HTTPServerError()

        ct = resp.headers.split('Content-Type')
        encoding = ct['charset'] if ct and 'charset' in ct else 'utf-8'
        data = self.parse_result_page(resp.data.decode(encoding, 'ignore').encode('utf-8'))
        data['p'] = p
        context.response['Content-Type'] = "application/json; charset=utf-8"
        context.response.data = data

    def parse_result_page(self, html):
        """ Parses an google search result page.
        :return: A dict object that contains extracted information.
        """
        soup = BeautifulSoup(html, 'html.parser')
        ires = soup.find('div', id='ires')
        if not ires:
            return {'stat': '', 'results': []}
        ga = ires.find_all('li', class_='g')
        if not ga:
            ga = ires.find_all('div', class_='g')
        results = []
        for g in ga:
            results.append(self.parse_result_element(g))

        tb = soup.find('div', id='resultStat')
        if not tb:
            tb = soup.find('div', id='topabar')
        stat = tb.text.encode('utf-8', 'ignore') if tb else ''
        return {'stat': stat, 'results': results}

    def result_page(self, kw, p=1):
        pass
