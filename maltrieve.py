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
import grequests
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

from threading import Thread
from Queue import Queue
from bs4 import BeautifulSoup


# TODO: use response, not filepath
def upload_vxcage(response):
    if os.path.exists(filepath):
        files = {'file': (os.path.basename(filepath), open(filepath, 'rb'))}
        url = 'http://localhost:8080/malware/add'
        headers = {'User-agent': 'Maltrieve'}
        try:
            # Note that this request does NOT go through proxies
            response = requests.post(url, headers=headers, files=files)
            response_data = response.json()
            logging.info("Submitted %s to VxCage, response was %s" % (os.path.basename(filepath),
                         response_data["message"]))
            logging.info("Deleting file as it has been uploaded to VxCage")
            try:
                os.remove(filepath)
            except:
                logging.info("Exception when attempting to delete file: %s", filepath)
        except:
            logging.info("Exception caught from VxCage")


# TODO: use response, not filepath
def upload_cuckoo(response):
    if os.path.exists(filepath):
        files = {'file': (os.path.basename(filepath), open(filepath, 'rb'))}
        url = 'http://localhost:8090/tasks/create/file'
        headers = {'User-agent': 'Maltrieve'}
        try:
            response = requests.post(url, headers=headers, files=files)
            response_data = response.json()
            logging.info("Submitted %s to cuckoo, task ID %s", filepath, response_data["task_id"])
        except:
            logging.info("Exception caught from Cuckoo")


def upload_viper(response):
    # not yet implemented
    pass


def process_xml_list(response)

    feed = feedparser.parse(response[2])
    urls = set()

    for entry in feed.entries:
        desc = entry.description
        url = desc.split(' ')[1].rstrip(',')
        if url == '-':
            url = desc.split(' ')[4].rstrip(',')
        url = re.sub('&amp;', '&', url)
        if not re.match('http', url):
            url = 'http://' + url
        urls += url

    return urls


def process_simple_list(response):
    urls = set([line if line.startswith('http') for line in response.split('\n')])
    return urls


def process_urlquery(response):
    # not yet implemented
    pass


def main():
    global hashes
    hashes = set()
    past_urls = set()

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
            past_urls = json.load(urlfile)
    elif os.path.exists('urls.obj'):
        with open('urls.obj', 'rb') as urlfile:
            past_urls = pickle.load(urlfile)

    source_urls = {'http://www.malwaredomainlist.com/hostslist/mdl.xml': process_xml_list,
                   'http://malc0de.com/rss': process_xml_list,
                   # 'http://www.malwareblacklist.com/mbl.xml',   # removed for now
                   'http://vxvault.siri-urz.net/URL_List.php': process_simple_list,
                   'http://urlquery.net/': process_url_query,
                   'http://support.clean-mx.de/clean-mx/rss?scope=viruses&limit=0%2C64': process_xml_list,
                   'http://malwareurls.joxeankoret.com/normal.txt': process_simple_list}
    headers = {'User-Agent': 'maltrieve'}

    reqs = [grequests.get(url, headers=headers, proxies=cfg['proxy']) for url in source_urls]
    source_lists = grequests.map(reqs)

    cfg['vxcage'] = args.vxcage or config.has_option('Maltrieve', 'vxcage')
    cfg['cuckoo'] = args.cuckoo or config.has_option('Maltrieve', 'cuckoo')
    cfg['logheaders'] = config.get('Maltrieve', 'logheaders')

    malware_urls = set()
    for response in source_lists:
        if response.status_code == 200:
            malware_urls.update(source_urls[response.url](response.text))

    malware_urls -= past_urls
    reqs = [grequests.get(url, headers=headers, proxies=cfg['proxy']) for url in malware_urls]
    malware_downloads = grequests.map(reqs)

    for each in malware_downloads:
        if each[1] != 200:
            continue
        if 'vxcage' in cfg:
            upload_vxcage(each)
        if 'cuckoo' in cfg:
            upload_cuckoo(each)
        if 'viper' in cfg:
            upload_viper(each)
        save_malware(each, cfg['dumpdir'])
        pasturls += each[0]

    if past_urls:
        logging.info('Dumping past URLs to file')
        with open('urls.json', 'w') as urlfile:
            json.dump(past_urls, urlfile)

    if hashes:
        with open('hashes.json', 'w') as hashfile:
            json.dump(hashes, hashfile)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
