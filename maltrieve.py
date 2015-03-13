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
import magic

from urlparse import urlparse
from threading import Thread
from Queue import Queue
from bs4 import BeautifulSoup

def upload_crits(response, md5, mime_type):
    if response:
        url_tag = urlparse(response.url)
        files = {'filedata': (md5, response.content)}
        headers = {'User-agent': 'Maltrieve'}
        zip_files = ['application/zip', 'application/gzip', 'application/x-7z-compressed']
        rar_files = ['application/x-rar-compressed']
        inserted_domain = False
        inserted_sample = False

        # submit domain / IP
        # TODO: identify if it is a domain or IP and submit accordingly
        url = "{0}/api/v1/domains/".format(config.get('Maltrieve', 'crits')) 
        domain_data = {
            'api_key': cfg['crits_key'],
            'username': cfg['crits_user'],
            'source': cfg['crits_source'],
            'domain': url_tag.netloc
        }
        try:
            # Note that this request does NOT go through proxies
            domain_response = requests.post(url, headers=headers, data=domain_data, verify=False)
            if domain_response.status_code == requests.codes.ok:
                domain_response_data = domain_response.json()
                logging.info("Submitted domain info for %s to Crits, response was %s" % (md5,
                             domain_response_data["message"]))
                if domain_response_data['return_code'] == 0: 
                    inserted_domain = True
        except:
            logging.info("Exception caught from Crits when submitting domain")

        # Submit sample
        url = "{0}/api/v1/samples/".format(config.get('Maltrieve', 'crits'))
        if mime_type in zip_files:
            file_type = 'zip'
        elif mime_type in rar_files:
            file_type = 'rar'
        else:
            file_type = 'raw'
        sample_data = {
            'api_key': cfg['crits_key'],
            'username': cfg['crits_user'],
            'source': cfg['crits_source'],
            'upload_type': 'file',
            'md5': md5,
            'file_format': file_type # must be type zip, rar, or raw
        }
        try:
            # Note that this request does NOT go through proxies
            sample_response = requests.post(url, headers=headers, files=files, data=sample_data, verify=False)
            if sample_response.status_code == requests.codes.ok:
                sample_response_data = sample_response.json()
                logging.info("Submitted sample info for %s to Crits, response was %s" % (md5,
                         sample_response_data["message"]))
                if sample_response_data['return_code'] == 0:
                    inserted_sample = True
        except:
            logging.info("Exception caught from Crits when submitting sample")

        # Create a relationship for the sample and domain        
        url = "{0}/api/v1/relationships/".format(config.get('Maltrieve', 'crits'))
        if (inserted_sample and inserted_domain):
            relationship_data = {
                'api_key': cfg['crits_key'],
                'username': cfg['crits_user'],
                'source': cfg['crits_source'],
                'right_type': domain_response_data['type'],
                'right_id': domain_response_data['id'],
                'left_type': sample_response_data['type'],
                'left_id': sample_response_data['id'],
                'rel_type': 'Downloaded_From',
                'rel_confidence': 'high',
                'rel_date': datetime.datetime.now()
            }
            try:
                # Note that this request does NOT go through proxies
                relationship_response = requests.post(url, headers=headers, data=relationship_data, verify=False)
                if relationship_response.status_code == requests.codes.ok:
                    relationship_response_data = relationship_response.json()
                    logging.info("Submitted relationship info for %s to Crits, response was %s" % (md5,
                                 relationship_response_data["message"]))
            except:
                logging.info("Relationship submission skipped. \n    Domain was %s\n    Sample response was %s\n    Domain response was %s\n" % (url_tag.netloc, sample_response.status_code, domain_response.status_code))
        else:
            logging.info("Skipping adding relationship. CRITs could not process domain or sample.")


def upload_vxcage(response, md5):
    if response:
        url_tag = urlparse(response.url)
        files = {'file': (md5, response.content)}
        tags = {'tags': url_tag.netloc + ',Maltrieve'}
        url = "{0}/malware/add".format(config.get('Maltrieve', 'vxcage'))
        headers = {'User-agent': 'Maltrieve'}
        try:
            # Note that this request does NOT go through proxies
            response = requests.post(url, headers=headers, files=files, data=tags)
            response_data = response.json()
            logging.info("Submitted %s to VxCage, response was %s" % (md5,
                         response_data["message"]))
        except:
            logging.info("Exception caught from VxCage")


# This gives cuckoo the URL instead of the file.
def upload_cuckoo(response, md5):
    if response:
        data = {'url': response.url}
        url = "{0}/tasks/create/url".format(config.get('Maltrieve', 'cuckoo'))
        headers = {'User-agent': 'Maltrieve'}
        #try:
        response = requests.post(url, headers=headers, data=data)
        response_data = response.json()
        logging.info("Submitted %s to Cuckoo, task ID %s", md5, response_data["task_id"])
        #except:
            #logging.info("Exception caught from Cuckoo")


def upload_viper(response, md5):
    if response:
        url_tag = urlparse(response.url)
        files = {'file': (md5, response.content)}
        tags = {'tags': url_tag.netloc + ',Maltrieve'}
        url = "{0}/file/add".format(config.get('Maltrieve', 'viper'))
        headers = {'User-agent': 'Maltrieve'}
        try:
            # Note that this request does NOT go through proxies
            response = requests.post(url, headers=headers, files=files, data=tags)
            response_data = response.json()
            logging.info("Submitted %s to Viper, response was %s" % (md5,
                         response_data["message"]))
        except:
            logging.info("Exception caught from Viper")


def exception_handler(request, exception):
    logging.info("Request for %s failed: %s" % (request, exception))


def save_malware(response, directory, black_list, white_list):
    url = response.url
    data = response.content
    mime_type = magic.from_buffer(data, mime=True)
    if mime_type in black_list:
        logging.info('%s in ignore list for %s', mime_type, url)
        return
    if white_list:
        if mime_type in white_list:
            pass
        else:
            logging.info('%s not in whitelist for %s', mime_type, url)
            return

    # Hash and log
    md5 = hashlib.md5(data).hexdigest()
    logging.info("%s hashes to %s" % (url, md5))

    # Assume that if viper or vxcage then we dont need to write to file as well.
    stored = False
    # Submit to external services
    if cfg['vxcage']:
        upload_vxcage(response, md5)
        stored = True
    if cfg['cuckoo']:
        upload_cuckoo(response, md5)
    if cfg['viper']:
        upload_viper(response, md5)
        stored = True
    if cfg['crits']:
        upload_crits(response, md5, mime_type)
        stored = True
    # else save to disk
    if not stored:
        if cfg['sort_mime']:
            # set folder per mime_type
            sort_folder = mime_type.replace('/', '_')
            if not os.path.exists(os.path.join(directory, sort_folder)):
                os.makedirs(os.path.join(directory, sort_folder))
            store_path = os.path.join(directory, sort_folder, md5)
        else:
            store_path = os.path.join(directory, md5)
        with open(store_path, 'wb') as f:
            f.write(data)
            logging.info("Saved %s to dump dir" % md5)
    return True


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
            urls.add('http://' + re.sub('&amp;', '&', a.text))
    return urls


def chunker(seq, size):
    return (seq[pos:pos + size] for pos in xrange(0, len(seq), size))


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
    parser.add_argument("-r", "--crits",
                        help="Dump the file to a Crits instance.",
                        action="store_true", default=False)
    parser.add_argument("-v", "--viper",
                        help="Dump the files to a Viper instance",
                        action="store_true", default=False)
    parser.add_argument("-x", "--vxcage",
                        help="Dump the file to a VxCage instance",
                        action="store_true", default=False)
    parser.add_argument("-c", "--cuckoo",
                        help="Enable Cuckoo analysis", action="store_true", default=False)
    parser.add_argument("-s", "--sort_mime",
                        help="Sort files by MIME type", action="store_true", default=False)

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

    if config.has_option('Maltrieve', 'User-Agent'):
        cfg['User-Agent'] = {'User-Agent': config.get('Maltrieve', 'User-Agent')}
    else:
        cfg['User-Agent'] = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)"

    cfg['sort_mime'] = args.sort_mime

    if cfg['proxy']:
        logging.info('Using proxy %s', cfg['proxy'])
        my_ip = requests.get('http://ipinfo.io/ip', proxies=cfg['proxy']).text
        logging.info('External sites see %s', my_ip)
        print "External sites see %s" % my_ip

    cfg['vxcage'] = args.vxcage or config.has_option('Maltrieve', 'vxcage')
    cfg['cuckoo'] = args.cuckoo or config.has_option('Maltrieve', 'cuckoo')
    cfg['viper'] = args.viper or config.has_option('Maltrieve', 'viper')
    cfg['logheaders'] = config.get('Maltrieve', 'logheaders') 

    # See if crits is configured. If so add config options for User/API
    cfg['crits'] = args.crits or config.has_option('Maltrieve', 'crits')
    if cfg['crits']:
        cfg['crits_user'] = config.get('Maltrieve', 'crits_user')
        cfg['crits_key'] = config.get('Maltrieve', 'crits_key')
        cfg['crits_source'] = config.get('Maltrieve', 'crits_source')

    black_list = []
    if config.has_option('Maltrieve', 'black_list'):
        black_list = config.get('Maltrieve', 'black_list').strip().split(',')

    white_list = False
    if config.has_option('Maltrieve', 'white_list'):
        white_list = config.get('Maltrieve', 'white_list').strip().split(',')

    # make sure we can open the directory for writing
    if args.dumpdir:
        cfg['dumpdir'] = args.dumpdir
    elif config.get('Maltrieve', 'dumpdir'):
        cfg['dumpdir'] = config.get('Maltrieve', 'dumpdir')
    else:
        cfg['dumpdir'] = '/tmp/malware'

    # Create the dir
    if not os.path.exists(cfg['dumpdir']):
        os.makedirs(cfg['dumpdir'])

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

    print "Processing source URLs"

    source_urls = {'https://zeustracker.abuse.ch/monitor.php?urlfeed=binaries': process_xml_list_desc,
                   'http://www.malwaredomainlist.com/hostslist/mdl.xml': process_xml_list_desc,
                   'http://malc0de.com/rss/': process_xml_list_desc,
                   'http://vxvault.siri-urz.net/URL_List.php': process_simple_list,
                   'http://urlquery.net/': process_urlquery,
                   'http://support.clean-mx.de/clean-mx/rss?scope=viruses&limit=0%2C64': process_xml_list_title,
                   'http://malwareurls.joxeankoret.com/normal.txt': process_simple_list}
    headers = {'User-Agent': 'Maltrieve'}

    reqs = [grequests.get(url, timeout=60, headers=headers, proxies=cfg['proxy']) for url in source_urls]
    source_lists = grequests.map(reqs)

    print "Completed source processing"

    headers['User-Agent'] = cfg['User-Agent']
    malware_urls = set()
    for response in source_lists:
        if hasattr(response, 'status_code') and response.status_code == 200:
            malware_urls.update(source_urls[response.url](response.text))

    print "Downloading samples, check log for details"

    malware_urls -= past_urls
    reqs = [grequests.get(url, headers=headers, proxies=cfg['proxy']) for url in malware_urls]
    for chunk in chunker(reqs, 32):
        malware_downloads = grequests.map(chunk)
        for each in malware_downloads:
            if not each or each.status_code != 200:
                continue
            md5 = save_malware(each, cfg['dumpdir'], black_list, white_list)
            if not md5:
                continue
            past_urls.add(each.url)

    print "Completed downloads"

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
