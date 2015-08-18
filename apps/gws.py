import sys
import json
import jinja2
sys.path.append('../')

from lync import *
from bs4 import BeautifulSoup


@WebApplication(root='/')
class GoogleSearch(object):
    def __init__(self, domain='www.google.com'):
        self.domain = domain
        self.ncr_cookie = self.gws_ncr_cookie()
        with open('pages/search.htm') as f:
            self.rtempl = jinja2.Template(f.read().decode('utf-8'))

    def gws_ncr_cookie(self):
        try:
            ncr = url_fetch('https://%s/ncr' % self.domain)
            if ncr.status == 200:
                return ''   # domain for current region is google.com
            if 301 <= ncr.status <= 302:
                if ncr.headers.has('Location', 'https://www.google.com/') and 'Set-Cookie' in ncr:
                    return ncr.headers['Set-Cookie'].split(';', 1)[0]
        except:
            pass
        return 'PREF=ID=1111111111111111:FF=0:LD=en:CR=2:TM=1439109218:LM=1439109218:V=1:S=v4gn7jZInBn-giuT'

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
        elem = {'title': '', 'url': '', 'site': '', 'st': ''}
        a = node.find('a')
        if a:
            elem['title'] = a.text.encode('utf-8', 'ignore')
            elem['url'] = self.shortcut(a['href'])
        cite = node.find('cite')
        if cite:
            elem['site'] = cite.text.encode('utf-8', 'ignore')
        st_span = node.find('span', class_='st')
        if st_span:
            elem['st'] = st_span.text.encode('utf-8', 'ignore')
        return elem

    def search(self, words, page=1):
        try:
            page = int(page)
        except ValueError:
            page = 1
        if isinstance(words, unicode):
            words = words.encode('utf-8', 'ignore')
        gurl = 'https://%s/search?q=%s&start=%d' % (self.domain, url_encode(words), (page-1)*10)
        headers = HTTPHeaders()
        headers['Cookie'] = self.ncr_cookie
        headers['Refer'] = 'https://%s/' % self.domain

        resp = url_fetch(gurl, headers=headers)
        if resp.status != 200:
            raise HTTPBadGateway()

        ct = resp.headers.split('Content-Type')
        encoding = ct.get('charset', 'utf-8')
        data = self.parse_result_page(resp.data.decode(encoding, 'ignore').encode('utf-8'))
        data['title'] = '%s - AMOOJ Search' % words
        data['q'] = words
        data['p'] = page
        return data

    @WebApplicationHandler(pattern='/json')
    def search_json(self, context, q, p=1, **kwargs):
        data = self.search(q, p)
        context.response['Content-Type'] = "application/json; charset=utf-8"
        context.response.data = json.dumps(data)

    def parse_result_page(self, html):
        """ Parses an google search result page.
        :return: A dict object that contains extracted information.
        """
        soup = BeautifulSoup(html, 'html.parser')
        ires = soup.find('div', id='ires')
        data = {'stat': '', 'results': []}
        if not ires:
            return data
        ga = ires.find_all('li', class_='g')
        if not ga:
            ga = ires.find_all('div', class_='g')
        results = []
        for g in ga:
            results.append(self.parse_result_element(g))

        stat = ''
        for id in ['resultStat', 'resultStats', 'topabar']:
            rs = soup.find('div', id=id)
            if rs:
                stat = rs.text.encode('utf-8', 'ignore')
                break
        data['stat'], data['results'] = stat, results
        return data

    @WebApplicationHandler(pattern='/')
    def result_page(self, context, q='', p=1, **kwargs):
        data = self.search(q, p)
        context.response.data = self.rtempl.render(data=data, errors='ignore').encode('utf-8')
        context.response['Content-Type'] = 'text/html; charset=utf-8'
