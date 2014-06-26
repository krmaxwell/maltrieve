#!/usr/bin/env python

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

import argparse
import datetime
import feedparser
import hashlib
import json
import logging
import os
import pickle
import re
import requests
import tempfile
import sys
import ConfigParser

from MultiPartForm import *
from threading import Thread
from Queue import Queue
from lxml import etree
from bs4 import BeautifulSoup


def get_malware(q, dumpdir):
    while True:
        url = q.get()
        logging.info("Fetched URL %s from queue", url)
        logging.info("%s items remaining in queue", q.qsize())
        try:
            mal_req = requests.get(url, proxies=cfg['proxy'])
        except requests.ConnectionError as e:
            logging.info("Could not connect to %s: %s" % (url, e))
            break
        mal = mal_req.content
        if mal:
            # REVIEW: Is this a big race condition problem?
            # TODO: store these in the JSON DB
            if 'logheaders' in cfg:
                logging.info(mal_req.headers)
            md5 = hashlib.md5(mal).hexdigest()
            # Is this a big race condition problem?
            if md5 not in hashes:
                logging.info("Found file %s at URL %s", md5, url)
                logging.debug("Going to put file in directory %s", dumpdir)
                if not os.path.isdir(dumpdir):
                    try:
                        logging.info("Creating dumpdir %s", dumpdir)
                        os.makedirs(dumpdir)
                    except OSError as exception:
                        if exception.errno != errno.EEXIST:
                            raise
                with open(os.path.join(dumpdir, md5), 'wb') as f:
                    f.write(mal)
                    logging.info("Stored %s in %s", md5, dumpdir)
                if 'vxcage' in cfg:
                    if os.path.exists(os.path.join(dumpdir, md5)):
                        f = open(os.path.join(dumpdir, md5), 'rb')
                        form = MultiPartForm()
                        form.add_file('file', md5, fileHandle=f)
                        form.add_field('tags', 'maltrieve')
                        body = str(form)
                        # TODO: check this carefully when porting to requests
                        url = 'http://localhost:8080/malware/add'
                        headers = {'User-agent': 'Maltrieve',
                                   'Content-type': form.get_content_type(),
                                   'Content-length': len(body)}
                        try:
                            # Note that this request does NOT go through proxies
                            response = requests.post(url, headers=headers, data=body)
                            response_data = response.json()
                            logging.info("Submitted %s to VxCage, response was %s",
                                         md5, response_data["message"])
                            logging.info("Deleting file as it has been uploaded to VxCage")
                            try:
                                os.remove(os.path.join(dumpdir, md5))
                            except:
                                logging.info("Exception when attempting to delete file: %s",
                                             os.path.join(dumpdir, md5))
                        except:
                            logging.info("Exception caught from VxCage")
                if 'cuckoo' in cfg:
                    f = open(os.path.join(dumpdir, md5), 'rb')
                    form = MultiPartForm()
                    form.add_file('file', md5, fileHandle=f)
                    body = str(form)
                    url = 'http://localhost:8090/tasks/create/file'
                    headers = {'User-agent': 'Maltrieve',
                               'Content-type': form.get_content_type(),
                               'Content-length': len(body)}
                    response = requests.post(url, headers=headers, data=body)
                    response_data = response.json()
                    logging.info("Submitted %s to cuckoo, task ID %s", md5,
                                 response_data["task_id"])
                hashes.add(md5)
        q.task_done()


def get_xml_list(feed_url, q):

    feed = feedparser.parse(feed_url)

    for entry in feed.entries:
        desc = entry.description
        logging.info('Parsing description %s', desc)
        url = desc.split(' ')[1].rstrip(',')
        if url == '-':
            url = desc.split(' ')[4].rstrip(',')
        url = re.sub('&amp;', '&', url)
        if not re.match('http', url):
            url = 'http://' + url
        push_malware_url(url, q)


def push_malware_url(url, q):
    url = url.strip()
    if url not in pasturls:
        logging.info('Adding new URL to queue: %s', url)
        pasturls.add(url)
        q.put(url)
    else:
        logging.info('Skipping previously processed URL: %s', url)


def main():
    global hashes
    hashes = set()
    global pasturls
    pasturls = set()

    malq = Queue()
    NUMTHREADS = 5
    now = datetime.datetime.now()

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--proxy",
                        help="Define HTTP proxy as address:port")
    parser.add_argument("-d", "--dumpdir",
                        help="Define dump directory for retrieved files")
    parser.add_argument("-l", "--logfile",
                        help="Define file for logging progress")
    parser.add_argument("-x", "--vxcage",
                        help="Dump the file to a VxCage instance running on the localhost",
                        action="store_true")
    parser.add_argument("-c", "--cuckoo",
                        help="Enable cuckoo analysis", action="store_true")

    global cfg
    cfg = dict()
    args = parser.parse_args()

    global config
    config = ConfigParser.ConfigParser()
    config.read('maltrieve.cfg')

    if args.logfile or config.get('Maltrieve', 'logfile'):
        if args.logfile:
            cfg['logfile'] = args.logfile
        else:
            cfg['logfile'] = config.get('Maltrieve', 'logfile')
        logging.basicConfig(filename=cfg['logfile'], level=logging.DEBUG,
                            format='%(asctime)s %(thread)d %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')
    else:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s %(thread)d %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')

    if args.proxy:
        cfg['proxy'] = {'http': args.proxy}
    elif config.has_option('Maltrieve', 'proxy'):
        cfg['proxy'] = {'http': config.get('Maltrieve', 'proxy')}
    else:
        cfg['proxy'] = None

    if cfg['proxy']:
        logging.info('Using proxy %s', cfg['proxy'])

    my_ip = requests.get('http://whatthehellismyip.com/?ipraw').text
    logging.info('External sites see %s', my_ip)

    # make sure we can open the directory for writing
    if args.dumpdir:
        cfg['dumpdir'] = args.dumpdir
    elif config.get('Maltrieve', 'dumpdir'):
        cfg['dumpdir'] = config.get('Maltrieve', 'dumpdir')
    else:
        cfg['dumpdir'] = '/tmp/malware'

    try:
        d = tempfile.mkdtemp(dir=cfg['dumpdir'])
    except Exception as e:
        logging.error('Could not open %s for writing (%s), using default',
                      cfg['dumpdir'], e)
        cfg['dumpdir'] = '/tmp/malware'
    else:
        os.rmdir(d)

    logging.info('Using %s as dump directory', cfg['dumpdir'])

    if os.path.exists('hashes.json'):
        with open('hashes.json', 'rb') as hashfile:
            hashes = json.load(hashfile)
    elif os.path.exists('hashes.obj'):
        with open('hashes.obj', 'rb') as hashfile:
            hashes = pickle.load(hashfile)

    if os.path.exists('urls.json'):
        with open('urls.json', 'rb') as urlfile:
            pasturls = json.load(urlfile)
    elif os.path.exists('urls.obj'):
        with open('urls.obj', 'rb') as urlfile:
            pasturls = pickle.load(urlfile)

    for i in range(NUMTHREADS):
        worker = Thread(target=get_malware, args=(malq, cfg['dumpdir'],))
        worker.setDaemon(True)
        worker.start()

    # TODO: refactor so we're just appending to the queue here
    get_xml_list('http://www.malwaredomainlist.com/hostslist/mdl.xml', malq)
    get_xml_list('http://malc0de.com/rss', malq)
    get_xml_list('http://www.malwareblacklist.com/mbl.xml', malq)

    # TODO: wrap these in functions?
    for url in requests.get('http://vxvault.siri-urz.net/URL_List.php', proxies=cfg['proxy']).text:
        if re.match('http', url):
            push_malware_url(url, malq)

    sacour_text = requests.get('http://www.sacour.cn/list/%d-%d/%d%d%d.htm' %
                               (now.year, now.month, now.year, now.month, now.day), proxies=cfg['proxy']).text
    if sacour_text:
        sacour_soup = BeautifulSoup(sacour_text)
        for url in sacour_soup.stripped_strings:
            if re.match("^http", url):
                push_malware_url(url, malq)

    urlquery_text = requests.get('http://urlquery.net/', proxies=cfg['proxy']).text
    if urlquery_text:
        urlquery_soup = BeautifulSoup(urlquery_text)
        for t in urlquery_soup.find_all("table", class_="test"):
            for a in t.find_all("a"):
                push_malware_url(a['title'], malq)

    ''' disabling due to parsing problems
    cleanmx_xml = etree.parse('http://support.clean-mx.de/clean-mx/xmlviruses.php?')
    for line in cleanmx_xml.xpath("//url"):
        url = re.sub('&amp;', '&', line.text)
        push_malware_url(url, malq)
    '''

    joxean_text = requests.get('http://malwareurls.joxeankoret.com/normal.txt', proxies=cfg['proxy']).text
    if joxean_text:
        for url in joxean_text:
            if not re.match("^#", url):
                push_malware_url(url, malq)

    cfg['vxcage'] = args.vxcage or config.has_option('Maltrieve', 'vxcage')
    cfg['cuckoo'] = args.cuckoo or config.has_option('Maltrieve', 'cuckoo')
    cfg['logheaders'] = config.get('Maltrieve', 'logheaders')

    malq.join()

    if pasturls:
        logging.info('Dumping past URLs to file')
        with open('urls.json', 'w') as urlfile:
            json.dump(pasturls, urlfile)

    if hashes:
        with open('hashes.json', 'w') as hashfile:
            json.dump(hashes, hashfile)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
