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
def upload_vxcage(filepath):
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
def upload_cuckoo(filepath):
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


def upload_viper(filepath, source_url):
    if os.path.exists(filepath):
        files = {'file': (os.path.basename(filepath), open(filepath, 'rb'))}
        url = 'http://localhost:8080/file/add'
        headers = {'User-agent': 'Maltrieve'}
        try:
            # Note that this request does NOT go through proxies
            response = requests.post(url, headers=headers, files=files)
            response_data = response.json()
            logging.info("Submitted %s to Viper, response was %s" % (os.path.basename(filepath),
                         response_data["message"]))
            logging.info("Deleting file as it has been uploaded to Viper")
            try:
                os.remove(filepath)
            except:
                logging.info("Exception when attempting to delete file: %s", filepath)
        except:
            logging.info("Exception caught from Viper")


def save_malware(response, directory):
    url = response.url
    data = response.content
    md5 = hashlib.md5(mal).hexdigest()
    logging.info("%s hashes to %s" % (url, md5))
    if not os.path.isdir(directory):
        try:
            os.makedirs(dumpdir)
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                raise
    with open(os.path.join(directory, md5), 'wb') as f:
        f.write(data)
        logging.info("Saved %s" % md5)
    return md5


def process_xml_list_desc(response):
    feed = feedparser.parse(response)
    urls = set()

    for entry in feed.entries:
        desc = entry.description
        url = desc.split(' ')[1].rstrip(',')
        if url == '':
            continue
        if url == '-':
            url = desc.split(' ')[4].rstrip(',')
        url = re.sub('&amp;', '&', url)
        if not re.match('http', url):
            url = 'http://' + url
        urls.add(url)

    return urls


def process_xml_list_title(response):
    feed = feedparser.parse(response)
    urls = set([re.sub('&amp;', '&', entry.title) for entry in feed.entries])
    return urls


def process_simple_list(response):
    urls = set([re.sub('&amp;', '&', line.strip()) for line in response.split('\n') if line.startswith('http')])
    return urls


def process_urlquery(response):
    soup = BeautifulSoup(response)
    urls = set()
    for t in soup.find_all("table", class_="test"):
        for a in t.find_all("a"):
          urls.add('http://'+re.sub('&amp;', '&', a.text))
    return urls


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

    source_urls = {'http://www.malwaredomainlist.com/hostslist/mdl.xml': process_xml_list_desc,
                   'http://malc0de.com/rss/': process_xml_list_desc,
                   # 'http://www.malwareblacklist.com/mbl.xml',   # removed for now
                   'http://vxvault.siri-urz.net/URL_List.php': process_simple_list,
                   'http://urlquery.net/': process_urlquery,
                   'http://support.clean-mx.de/clean-mx/rss?scope=viruses&limit=0%2C64': process_xml_list_title,
                   'http://malwareurls.joxeankoret.com/normal.txt': process_simple_list}
    headers = {'User-Agent': 'maltrieve'}

    reqs = [grequests.get(url, timeout=60, headers=headers, proxies=cfg['proxy']) for url in source_urls]
    source_lists = grequests.map(reqs)

    cfg['vxcage'] = args.vxcage or config.has_option('Maltrieve', 'vxcage')
    cfg['cuckoo'] = args.cuckoo or config.has_option('Maltrieve', 'cuckoo')
    cfg['logheaders'] = config.get('Maltrieve', 'logheaders')

    malware_urls = set()
    for response in source_lists:
        if hasattr(response, 'status_code') and response.status_code == 200:
            malware_urls.update(source_urls[response.url](response.text))

    malware_urls -= past_urls
    reqs = [grequests.get(url, headers=headers, proxies=cfg['proxy']) for url in malware_urls]
    malware_downloads = grequests.map(reqs)

    for each in malware_downloads:
        if each.status_code != 200:
            continue
        md5 = save_malware(each, cfg['dumpdir'])
        if 'vxcage' in cfg:
            upload_vxcage(md5)
        if 'cuckoo' in cfg:
            upload_cuckoo(md5)
        if 'viper' in cfg:
            upload_viper(each)
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
