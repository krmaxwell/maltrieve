# Copyright 2013 Kyle Maxwell
# Includes code from mwcrawler, (c) 2012 Ricardo Dias. Used under license.

# Maltrieve - retrieve malware from the source

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/

import urllib2
import logging
import argparse
import tempfile
import re
import hashlib
import os
import datetime
import xml.etree.ElementTree as ET
from threading import Thread 
from Queue import Queue

from bs4 import BeautifulSoup

from malutil import *

NUMTHREADS = 4
hashes = set()
pasturls = set()
dumpdir = ''
now = datetime.datetime.now()


def get_malware(q):
    while True:
        url = q.get()
        logging.info("Fetched URL %s from queue", url)
        mal = get_URL(url)
        if mal:
            malfile=mal.read()
            md5 = hashlib.md5(malfile).hexdigest()
            # Is this a big race condition problem?
            if md5 not in hashes:
                logging.info("Found file %s at URL %s", md5, url)
                # store the file and log the data
                with open(os.path.join(dumpdir, md5), 'wb') as f:
                    f.write(malfile)
                hashes.add(md5)
                pasturls.add(url)
        q.task_done()

def get_XML_list(url,q):
    malwareurls = []
    descriptions = []

    tree = get_XML(url)
    if tree:
        descriptions = tree.findall('channel/item/description')

    for d in descriptions:
        logging.info('Parsing description %s', d)
        url = d.text.split(' ')[1].rstrip(',')
        if url == '-':
            url = d.text.split(' ')[4].rstrip(',')
        url = re.sub('&amp;','&',url).rstrip()
        if not re.match('http',url):
            url = 'http://'+url
        malwareurls.append(url)

    for url in malwareurls:
        push_mal_URL(url,q)

def push_malware_URL(url,q):
    if url not in pasturls:
        q.put(url)

# ----
# Main
# ----

if __name__ == "__main__":
    malq = Queue()

    parser = argparse.ArgumentParser()
#   parser.add_argument("-t", "--thug", help="Enable thug analysis", action="store_true")
    parser.add_argument("-p", "--proxy", 
                        help="Define HTTP proxy as address:port")
    parser.add_argument("-d", "--dumpdir", 
                        help="Define dump directory for retrieved files")
    parser.add_argument("-l", "--logfile", 
                        help="Define file for logging progress")
    args = parser.parse_args()

    # Enable thug support 
    # https://github.com/buffer/thug
    # TODO: rewrite and test
    '''
    try:
        if args.thug:
            loadthug()
    except Exception as e:
        logging.warning('Could not enable thug (%s)', e)
    '''

    if args.proxy:
        proxy = urllib2.ProxyHandler({'http': args.proxy})
        opener = urllib2.build_opener(proxy)
        urllib2.install_opener(opener)
        logging.info('Using proxy %s', args.proxy)
        my_ip = urllib2.urlopen('http://whatthehellismyip.com/?ipraw').read()
        logging.info('External sites see %s',my_ip)

    # http://stackoverflow.com/questions/14574889/verify-directory-write-privileges
    if args.dumpdir:
        try:
            d = tempfile.mkdtemp(dir=args.dumpdir)
            dumpdir=args.dumpdir
        except Exception as e:
            logging.error('Could not open %s for writing (%s), using default', 
                          dumpdir, e)
            dumpdir = '/tmp/malware/unsorted'
        else:
            os.rmdir(d)
    else:
        dumpdir = '/tmp/malware/unsorted'

    if args.logfile:
        logging.basicConfig(filename=args.logfile, level=logging.DEBUG, 
                            format='%(asctime)s %(thread)d %(message)s', 
                            datefmt='%Y-%m-%d %H:%M:%S')
    else:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime) %(message)s', 
                            datefmt='%Y-%m-%d %H:%M:%S')

    if os.path.exists('hashes.obj'):
        with open('hashes.obj','rb') as hashfile:
            hashes = pickle.load(hashfile)

    if os.path.exists('urls.obj'):
        with open('urls.obj', 'rb') as urlfile:
            pasturls = pickle.load(urlfile)

    for i in range(NUMTHREADS):
        worker = Thread(target=get_malware, args=(malq,))
        worker.setDaemon(True)
        worker.start()
    
    get_XML_list('http://www.malwaredomainlist.com/hostslist/mdl.xml',malq)
    get_XML_list('http://malc0de.com/rss',malq)
    
    # TODO: wrap these in a function
    for url in get_URL('http://vxvault.siri-urz.net/URL_List.php'):
        if re.match('http', url):
            push_malware_URL(url,malq)
    
    sacourtext=get_URL('http://www.sacour.cn/showmal.asp?month=%d&year=%d' % 
                  (now.month, now.year)).read()
    for url in re.sub('\<[^>]*\>','\n',sacourtext).splitlines():
        push_malware_URL(url,malq)
    
    # appears offline
    # minotaur(parse('http://minotauranalysis.com/malwarelist-urls.aspx'))
    # appears offline
    # malwarebl(parse('http://www.malwareblacklist.com/mbl.xml'))
    
    malq.join()

    with open('hashes.obj','wb') as hashfile:
        pickle.dump(hashfile, hashes)

    with open('urls.obj', 'wb') as urlfile:
        pickle.dump(urlfile, pasturls)
