#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import sys
import time
import codecs
import gevent
import logging
import urlnorm
import datetime
import urllib
import urlparse
import requests
import tldextract

from gsb import client
from pprint import pprint
from gsb import datastore
from bs4 import BeautifulSoup
from selenium import webdriver
from spam.surbl import SurblChecker
from spam.spamhaus import SpamHausChecker

# Unicode fixup
UTF8Writer = codecs.getwriter('utf8')
sys.stdout = UTF8Writer(sys.stdout)

urlsseen = set()
urlschecked = dict()
cookiejar = None
ds = None
sbc = None

safebrowse_apikey = 'YourAPIKeyHere'
debug = False
want_safebrowse = True
want_spamhaus = False

def RateLimited(maxPerSecond):
    """
        Decorator for rate limiting
    """
    minInterval = 1.0 / float(maxPerSecond)
    def decorate(func):
        lastTimeCalled = [0.0]
        def rateLimitedFunction(*args,**kargs):
            elapsed = time.clock() - lastTimeCalled[0]
            leftToWait = minInterval - elapsed
            if leftToWait>0:
                time.sleep(leftToWait)
            ret = func(*args,**kargs)
            lastTimeCalled[0] = time.clock()
            return ret
        return rateLimitedFunction
    return decorate

def safebrowse_init(apikey, storename):

    global ds, sbc

    chunk_range_str = None
    num_expressions = None
    num_addchunks = None
    num_subchunks = None

    ds = datastore.DataStore(storename)

    sbc = client.Client(ds,
                        apikey=apikey,
                        use_mac=True)


def find_url(txt):
    urlfinder = re.compile( # stolen from django
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    urllist = [ mgroups[0] for mgroups in urlfinder.findall(txt)]
    return urllist

def fix_urls(urls, hostinfo):

    ret = []
    for url in urls:
        if url:
            if not urlparse.urlparse(url).scheme:
                if not url.startswith('//'):

                    url = url.encode('utf8','ignore')
                    url = hostinfo['scheme'] + "://" + hostinfo['hostname'] + '/' + url
                    url = urlnorm.norm(url)
                else:
                    url = hostinfo['scheme'] + ':' + url


                if url.endswith('#'):
                    url = url[:-1]

                if url.startswith('javascript:'):
                    continue

                #print "fixed up url on %s: %s" % (hostinfo['hostname'], url)
            ret.append(url)
    return ret

def get_domain(url):
    domain = tldextract.extract(url)
    result = domain.domain + "." + domain.tld
    return result


def check_surbl(url):
    global urlschecked

    domain = get_domain(url)

    # check for links we cannot handle
    if url.startswith('http') or url.startswith('https'):
        # short cirquit (caching is good!)
        if urlschecked.has_key("surbl-" + domain):
            return urlschecked["surbl-" + domain]
        checker = SurblChecker()
        try:
            ret = checker.is_spam(url)
        except IndexError as e:
            print "Whoops, trying again later."
            return False
        urlschecked["surbl-" + domain] = ret
        return ret
    else:
        return False

def check_spamhaus(url):
    global urlschecked, want_spamhaus

    domain = get_domain(url)

    if not want_spamhaus:
        return False

    # check for links we cannot handle
    if url.startswith('http') or url.startswith('https'):
        # short cirquit (caching is good!)
        if urlschecked.has_key("sh-" + domain):
            return urlschecked["sh-" + domain]
        checker = SpamHausChecker()
        try:
            ret = checker.is_spam(url)
        except Exception as e:
            print "Whoops, trying again later: %s" % e
            return False
        urlschecked["sh-" + domain] = ret
        return ret
    else:
        return False

def check_safebrowse(url):
    global urlschecked, want_safebrowse, cookiejar, sbc

    ret = False

    if not want_safebrowse:
        return False

    if url.startswith('javascript:'):
        ret = False

    try:
        url = urllib.quote(url, safe="%/:=&?~#+!$,;'@()*[]").encode('utf-8')

        url = get_domain(url)

        if urlschecked.has_key('sb-' + url):
            return urlschecked['sb-' + url]

        ## Lookup API (slow!)
        # checkurl = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=firefox&apikey=%s&appver=1.5.2&pver=3.0" % safebrowse_apikey
        # payload = {'1': url}
        # ret = requests.post(checkurl, data=payload)

        matches = sbc.CheckUrl(url, debug_info=True)
        if len(matches) == 0:
            ret = False
        else:
            for listname, match, addchunknum in matches:
                if ret:
                    ret += '%s: addchunk number: %d: %s\n' % (listname, addchunknum, match)
                else:
                    ret = '%s: addchunk number: %d: %s\n' % (listname, addchunknum, match)


    except Exception as ex:
        print "SBC: Skipped this url: %s\nReason: %s" % (url, ex)
        ret = False

    urlschecked['sb-' + url] = ret

    return ret

def js_click(url, urllist, urlindex):

    # crap, a javascript redirect. Whip out selenium
    print "JS: %s" % url
    driver = webdriver.PhantomJS()

    prevurl = urls[urlindex - 1]
    print "JS: Loading %s first for context." % prevurl
    # get previous page for context
    driver.get(prevurl)
    # wait for page load
    while prevurl == driver.current_url:
        time.sleep(2)

    # get js link
    driver.get(url)
    while url == driver.current_url:
        time.sleep(2)

    url = driver.current_url
    print "Javascript url resolved into %s" % url

def extract_urls(r, hostinfo):

    global urlsseen

    # Make sure r actually contains something, otherwise
    # we throw exceptions
    if r == None:
        return

    urls = []

    # check mime type and act accordingly
    if r.headers['content-type'].startswith('text/html'):
        soup = BeautifulSoup(r.content)

        urls = [link.get('src') for link in soup.find_all('script')]
        urls += [link.get('href') for link in soup.find_all('a')]
        urls += [link.get('src') for link in soup.find_all('iframe')]
        urls += [link.get('href') for link in soup.find_all('link')]
        urls += [link.get('url') for link in soup.find_all('applet')]
        urls += [link.get('data') for link in soup.find_all('object')]
        print "Found %d references in markup" % len(urls)
    elif r.headers['content-type'].startswith('application/javascript'):
        # just look for stuff that looks like a URI
        urls = find_url(r.text)
        pprint(urls)
    elif r.headers['content-type'].startswith('text/plain'):
        # just look for stuff that looks like a URI
        urls = find_url(r.text)
        pprint(urls)
    else:
        # anything else?
        return []

    if urls:
        # fix up b0rked urls (e.g. relative links)
        urls = fix_urls(urls, hostinfo)

        # preventively strip out urls we already seen
        for url in urls:
            if url in urlsseen:
                urls.remove(url)

        for url in urls:
            if check_surbl(url):
                print "Malicious domain found on %s:\n\t %s" % (hostinfo['fullurl'], url)
                f = open('assets.txt', 'a')
                f.write('SURBL :' + str(hostinfo['fullurl']) + '\t=>\t' + url + '\n')
                f.close
            if check_spamhaus(url):
                print "Spamhaus domain found on %s:\n\t %s" % (hostinfo['fullurl'], url)
                f = open('assets.txt', 'a')
                f.write('SPAMHAUS:' + str(hostinfo['fullurl']) + '\t=>\t' + url + '\n')
                f.close
            ret = check_safebrowse(url)
            if ret:
                print "SAFEBROWSE: %url -> %s" % (hostinfo['fullurl'], ret)
                f = open('assets.txt', 'a')
                f.write('SAFEBROWSE: %s -> %s\n' % (hostinfo['fullurl'], ret))
                f.close


        print "Saw %d new links on this page." % len(urls)
        return urls
    else:
        return []


def print_url(r, *args, **kwargs):
    global urlsseen

    if r == None:
        return

    urlsseen.add(r.url)


def recurse_url(urls, domain):
    global urlsseen, cookiejar

    domain = get_domain(domain)

    while True:
        if len(urls) == 0:
            return

        # prune
        for url in urls:
            if url in urlsseen:
                urls.remove(url)

        print "urls contains %d elements" % len(urls)

        # remove None values from urls
        urls = [x for x in urls if x is not None]

        hooks = {'response': print_url}

        rs = []
        urlindex = 0
        for url in urls:

            # don't investigate a link if we have already seen it.
            if url in urlsseen:
                #print "Not fetching %s. (%d in cache, %d pending)" % (url, len(urlsseen), len(urls))
                if url in urls:
                    urls.remove(url)
                continue
            else:
                urlsseen.add(url)

            if get_domain(url) != domain:
                #print "%s != %s, not fetching" % (get_domain(url), domain)
                continue

            if url.startswith('javascript:'):
                js_click(url, urls, urlindex)
                continue


            if url.startswith('mailto:'):
                continue

            if url:
                url_lists = []

                print "Fetching %s. (%d in cache, %d pending)" % (url, len(urlsseen), len(urls))
                headers = {  # Let's pretend we're internet explorer, because we can
                    'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.6; Windows NT 6.1; Trident/5.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727) 3gpp-gba UNTRUSTED/1.0',
                }
                try:
                    response = requests.get(url, hooks=hooks, headers=headers, cookies=cookiejar)
                except Exception as ex:
                    print "Whoops... %s" % ex
                    continue # fuck it

                cookiejar = response.cookies
                pprint(cookiejar.get_dict())


                hostinfo = { 'hostname': urlparse.urlparse(url).hostname.encode('utf8'),
                             'scheme': urlparse.urlparse(url).scheme.encode('utf8'),
                             'fullurl':url.encode('utf8')}
                items = extract_urls(response, hostinfo)
                url_lists.append(items)
                url_lists = [x for x in url_lists if x is not None]
                urls += sum(url_lists, []) # flatten
                urlindex += 1


def main():
    global debug, safebrowse_apikey

    if debug:
        logging.basicConfig(level=logging.DEBUG)

    if want_safebrowse:
        print "Checking datastore for SBC"
        safebrowse_init(safebrowse_apikey, 'sbcstore')

    if len(sys.argv) < 2:
        sys.exit('Need list of urls to crawl')

    urllist = []
    for line in open(sys.argv[1]):
        url = line.strip()
        if not url.startswith('http'):
            url = 'http://' + url
        print "added %s" % url
        urllist.append(url)

    for url in urllist:
        recurse_url([url], url)

if __name__ == '__main__':
    sys.exit(main())
