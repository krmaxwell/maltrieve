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

from bs4 import BeautifulSoup
import urllib2, logging, argparse, tempfile, re
from threading import Thread 
from Queue import Queue
import xml.etree.ElementTree as ET

from malutil import *

NUMTHREADS = 4

def getmalware(q):
    while True:
        logging.info("Fetching URL from queue")
        url=q.get()
        mal = geturl(url)
        # hash the malware
        # if we don't already have it, determine file type
	# store the file and log the data
        q.task_done()

def getxmllist(url,q):
    malwareurls = []

    tree = getxml(url)
    descriptions = tree.findall('channel/item/description')
    for d in descriptions:
        logging.info('Parsing description %s', d)
        url = d.text.split(' ')[1].rstrip(',')
        if url == '-':
            url = d.text.split(' ')[4].rstrip(',')
        url = re.sub('&amp;','&',url)
        if not re.match('http',url):
            url = 'http://'+url
        malwareurls.append(url)

    for url in malwareurls:
        pushmalurl(url,q)

def pushmalurl(url,q):
    if url not in pasturls:
        q.put(url)

# ----
# Main
# ----

if __name__ == "__main__":
    malq = Queue()

    parser = argparse.ArgumentParser()
#   parser.add_argument("-t", "--thug", help="Enable thug analysis", action="store_true")
    parser.add_argument("-p", "--proxy", help="Define HTTP proxy as address:port")
    parser.add_argument("-d", "--dumpdir", help="Define dump directory for retrieved files")
    parser.add_argument("-l", "--logfile", help="Define file for logging progress")
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

    # proxy support
    if args.proxy:
        proxy = urllib2.ProxyHandler({'http': args.proxy})
        opener = urllib2.build_opener(proxy)
        urllib2.install_opener(opener)
        logging.info('Using proxy %s', args.proxy)
        my_ip = urllib2.urlopen('http://whatthehellismyip.com/?ipraw').read()
        logging.info('External sites see %s',my_ip)

    # dump directory
    # http://stackoverflow.com/questions/14574889/verify-directory-write-privileges
    if args.dumpdir:
        try:
            d = tempfile.mkdtemp(dir=args.dumpdir)
            dumpdir=args.dumpdir
        except Exception as e:
            logging.error('Could not open %s for writing (%s), using default', dumpdir, e)
            dumpdir = '/tmp/malware/unsorted'
        else:
            os.rmdir(d)
    else:
        dumpdir = '/tmp/malware/unsorted'

    if args.logfile:
        logging.basicConfig(filename=args.logfile, level=logging.DEBUG, format='%(asctime)s %(thread)d %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    else:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime) %message(s)', datefmt='%Y-%m-%d %H:%M:%S')

    for i in range(NUMTHREADS):
        worker = Thread(target=getmalware, args=(malq,))
        worker.setDaemon(True)
        worker.start()
    
    # sources:
    getxmllist('http://www.malwaredomainlist.com/hostslist/mdl.xml')
    getxmllist('http://malc0de.com/rss')
    
    # wrap these in a function
    for url in geturl('http://vxvault.siri-urz.net/URL_List.php'):
        if re.match('http', url):
            pushmalwareurl(url,malq)
    
    sacour=geturl('http://www.sacour.cn/showmal.asp?month=%d&year=%d' % (now.month, now.year)).read()
    for url in re.sub('\<[^>]*\>','\n',sacourtext).splitlines():
        pushmalwareurl(url,malq)
    
    # appears offline
    # minotaur(parse('http://minotauranalysis.com/malwarelist-urls.aspx'))
    # appears offline
    # malwarebl(parse('http://www.malwareblacklist.com/mbl.xml'))
    
    malq.join()
