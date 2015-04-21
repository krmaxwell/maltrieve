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
import ConfigParser
import datetime
import hashlib
import json
import logging
import os
import re
import resource
import sys
import tempfile
from urlparse import urlparse

import feedparser
import grequests
import magic
import requests
from bs4 import BeautifulSoup


class config(object):

    """ Class for holding global configuration setup """

    def __init__(self, args, filename='maltrieve.cfg'):
        self.configp = ConfigParser.ConfigParser()
        self.configp.read(filename)

        if args.logfile or self.configp.get('Maltrieve', 'logfile'):
            if args.logfile:
                self.logfile = args.logfile
            else:
                self.logfile = self.configp.get('Maltrieve', 'logfile')
            logging.basicConfig(filename=self.logfile, level=logging.DEBUG,
                                format='%(asctime)s %(thread)d %(message)s',
                                datefmt='%Y-%m-%d %H:%M:%S')
        else:
            logging.basicConfig(level=logging.DEBUG,
                                format='%(asctime)s %(thread)d %(message)s',
                                datefmt='%Y-%m-%d %H:%M:%S')
        if args.proxy:
            self.proxy = {'http': args.proxy}
        elif self.configp.has_option('Maltrieve', 'proxy'):
            self.proxy = {'http': self.configp.get('Maltrieve', 'proxy')}
        else:
            self.proxy = None

        if self.configp.has_option('Maltrieve', 'User-Agent'):
            self.useragent = {'User-Agent': self.configp.get('Maltrieve', 'User-Agent')}
        else:
            # Default to IE 9
            self.useragent = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)"

        self.sort_mime = args.sort_mime

        if self.configp.has_option('Maltrieve', 'black_list'):
            self.black_list = self.configp.get('Maltrieve', 'black_list').strip().split(',')
        else:
            self.black_list = []

        if self.configp.has_option('Maltrieve', 'white_list'):
            self.white_list = self.configp.get('Maltrieve', 'white_list').strip().split(',')
        else:
            self.white_list = False

        if args.inputfile:
            self.inputfile = args.inputfile
        else:
            self.inputfile = None

        # make sure we can open the directory for writing
        if args.dumpdir:
            self.dumpdir = args.dumpdir
        elif self.configp.get('Maltrieve', 'dumpdir'):
            self.dumpdir = self.configp.get('Maltrieve', 'dumpdir')
        else:
            self.dumpdir = '/tmp/malware'

        # Create the dir
        if not os.path.exists(self.dumpdir):
            try:
                os.makedirs(self.dumpdir)
            except OSError:
                logging.error('Could not create %s, using default', self.dumpdir)
                self.dumpdir = '/tmp/malware'

        try:
            fd, temp_path = tempfile.mkstemp(dir=self.dumpdir)
        except OSError:
            logging.error('Could not open %s for writing, using default', self.dumpdir)
            self.dumpdir = '/tmp/malware'
        else:
            os.close(fd)
            os.remove(temp_path)

        logging.info('Using %s as dump directory', self.dumpdir)
        self.logheaders = self.configp.get('Maltrieve', 'logheaders')

        # TODO: Merge these
        self.vxcage = args.vxcage or self.configp.has_option('Maltrieve', 'vxcage')
        self.cuckoo = args.cuckoo or self.configp.has_option('Maltrieve', 'cuckoo')
        self.viper = args.viper or self.configp.has_option('Maltrieve', 'viper')

        # CRITs
        if args.crits or self.configp.has_option('Maltrieve', 'crits'):
            self.crits = args.crits or self.configp.get('Maltrieve', 'crits')
            self.crits_user = self.configp.get('Maltrieve', 'crits_user')
            self.crits_key = self.configp.get('Maltrieve', 'crits_key')
            self.crits_source = self.configp.get('Maltrieve', 'crits_source')
        else:
            self.crits = False

    def check_proxy(self):
        if self.proxy:
            logging.info('Using proxy %s', self.proxy)
            my_ip = requests.get('http://ipinfo.io/ip', proxies=self.proxy).text
            logging.info('External sites see %s', my_ip)
            print 'External sites see {ip}'.format(ip=my_ip)


def upload_crits(response, md5, cfg):
    if response:
        url_tag = urlparse(response.url)
        mime_type = magic.from_buffer(response.content, mime=True)
        files = {'filedata': (md5, response.content)}
        headers = {'User-agent': 'Maltrieve'}
        zip_files = ['application/zip', 'application/gzip', 'application/x-7z-compressed']
        rar_files = ['application/x-rar-compressed']
        inserted_domain = False
        inserted_sample = False

        # submit domain / IP
        # TODO: identify if it is a domain or IP and submit accordingly
        url = "{srv}/api/v1/domains/".format(srv=cfg.crits)
        domain_data = {
            'api_key': cfg.crits_key,
            'username': cfg.crits_user,
            'source': cfg.crits_source,
            'domain': url_tag.netloc
        }
        try:
            # Note that this request does NOT go through proxies
            logging.debug("Domain submission: %s|%r", url, domain_data)
            domain_response = requests.post(url, headers=headers, data=domain_data)
            # pylint says "Instance of LookupDict has no 'ok' member" but it's wrong, I checked
            if domain_response.status_code == requests.codes.ok:
                domain_response_data = domain_response.json()
                if domain_response_data['return_code'] == 0:
                    inserted_domain = True
                else:
                    logging.info("Submitted domain info %s for %s to CRITs, response was %s",
                                 domain_data['domain'], md5, domain_response_data)
            else:
                logging.info("Submission of %s failed: %d", url, domain_response.status_code)
        except requests.exceptions.ConnectionError:
            logging.info("Could not connect to CRITs when submitting domain %s", domain_data['domain'])
        except requests.exceptions.HTTPError:
            logging.info("HTTP error when submitting domain %s to CRITs", domain_data['domain'])

        # Submit sample
        url = "{srv}/api/v1/samples/".format(srv=cfg.crits)
        if mime_type in zip_files:
            file_type = 'zip'
        elif mime_type in rar_files:
            file_type = 'rar'
        else:
            file_type = 'raw'
        sample_data = {
            'api_key': cfg.crits_key,
            'username': cfg.crits_user,
            'source': cfg.crits_source,
            'upload_type': 'file',
            'md5': md5,
            'file_format': file_type  # must be type zip, rar, or raw
        }
        try:
            # Note that this request does NOT go through proxies
            sample_response = requests.post(url, headers=headers, files=files, data=sample_data, verify=False)
            # pylint says "Instance of LookupDict has no 'ok' member" but it's wrong, I checked
            if sample_response.status_code == requests.codes.ok:
                sample_response_data = sample_response.json()
                if sample_response_data['return_code'] == 0:
                    inserted_sample = True
                else:
                    logging.info("Submitted sample %s to CRITs, response was %r", md5, sample_response_data)
            else:
                logging.info("Submission of sample %s failed: %d}", md5, sample_response.status_code)
        except requests.exceptions.ConnectionError:
            logging.info("Could not connect to CRITs when submitting sample %s", md5)
        except requests.exceptions.HTTPError:
            logging.info("HTTP error when submitting sample %s to CRITs", md5)

        # Create a relationship for the sample and domain
        url = "{srv}/api/v1/relationships/".format(srv=cfg.crits)
        if (inserted_sample and inserted_domain):
            relationship_data = {
                'api_key': cfg.crits_key,
                'username': cfg.crits_user,
                'source': cfg.crits_source,
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
                # pylint says "Instance of LookupDict has no 'ok' member"
                if relationship_response.status_code != requests.codes.ok:
                    logging.info("Submitted relationship info for %s to CRITs, response was %r",
                                 md5, domain_response_data)
            except requests.exceptions.ConnectionError:
                logging.info("Could not connect to CRITs when submitting relationship for sample %s", md5)
            except requests.exceptions.HTTPError:
                logging.info("HTTP error when submitting relationship for sample %s to CRITs", md5)
                return True
        else:
            return False


def upload_vxcage(response, md5, cfg):
    if response:
        url_tag = urlparse(response.url)
        files = {'file': (md5, response.content)}
        tags = {'tags': url_tag.netloc + ',Maltrieve'}
        url = "{srv}/malware/add".format(srv=cfg.vxcage)
        headers = {'User-agent': 'Maltrieve'}
        try:
            # Note that this request does NOT go through proxies
            response = requests.post(url, headers=headers, files=files, data=tags)
            response_data = response.json()
            logging.info("Submitted %s to VxCage, response was %d", md5, response_data["message"])
        except requests.exceptions.ConnectionError:
            logging.info("Could not connect to VxCage, will attempt local storage")
            return False
        else:
            return True


# This gives cuckoo the URL instead of the file.
def upload_cuckoo(response, md5, cfg):
    if response:
        data = {'url': response.url}
        url = "{srv}/tasks/create/url".format(srv=cfg.cuckoo)
        headers = {'User-agent': 'Maltrieve'}
        try:
            response = requests.post(url, headers=headers, data=data)
            response_data = response.json()
            logging.info("Submitted %s to Cuckoo, task ID %d", md5, response_data["task_id"])
        except requests.exceptions.ConnectionError:
            logging.info("Could not connect to Cuckoo, will attempt local storage")
            return False
        else:
            return True


def upload_viper(response, md5, cfg):
    if response:
        url_tag = urlparse(response.url)
        files = {'file': (md5, response.content)}
        tags = {'tags': url_tag.netloc + ',Maltrieve'}
        url = "{srv}/file/add".format(srv=cfg.viper)
        headers = {'User-agent': 'Maltrieve'}
        try:
            # Note that this request does NOT go through proxies
            response = requests.post(url, headers=headers, files=files, data=tags)
            response_data = response.json()
            logging.info("Submitted %s to Viper, response was %s", md5, response_data["message"])
        except requests.exceptions.ConnectionError:
            logging.info("Could not connect to Viper, will attempt local storage")
            return False
        else:
            return True


def save_malware(response, cfg):
    url = response.url
    data = response.content
    mime_type = magic.from_buffer(data, mime=True)
    if mime_type in cfg.black_list:
        logging.info('%s in ignore list for %s', mime_type, url)
        return False
    if cfg.white_list:
        if mime_type in cfg.white_list:
            pass
        else:
            logging.info('%s not in whitelist for %s', mime_type, url)
            return False

    # Hash and log
    md5 = hashlib.md5(data).hexdigest()
    logging.info("%s hashes to %s", url, md5)

    # Assume that external repo means we don't need to write to file as well.
    stored = False
    # Submit to external services

    # TODO: merge these
    if cfg.vxcage:
        stored = upload_vxcage(response, md5, cfg) or stored
    if cfg.cuckoo:
        stored = upload_cuckoo(response, md5, cfg) or stored
    if cfg.viper:
        stored = upload_viper(response, md5, cfg) or stored
    if cfg.crits:
        stored = upload_crits(response, md5, cfg) or stored
    # else save to disk
    if not stored:
        if cfg.sort_mime:
            # set folder per mime_type
            sort_folder = mime_type.replace('/', '_')
            if not os.path.exists(os.path.join(cfg.dumpdir, sort_folder)):
                os.makedirs(os.path.join(cfg.dumpdir, sort_folder))
            store_path = os.path.join(cfg.dumpdir, sort_folder, md5)
        else:
            store_path = os.path.join(cfg.dumpdir, md5)
        with open(store_path, 'wb') as f:
            f.write(data)
            logging.info("Saved %s to dump dir", md5)
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


def setup_args(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--proxy",
                        help="Define HTTP proxy as address:port")
    parser.add_argument("-d", "--dumpdir",
                        help="Define dump directory for retrieved files")
    parser.add_argument("-i", "--inputfile", help="File of URLs to process")
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
    parser.add_argument("--config", help="Alternate config file (default maltrieve.cfg)")

    return parser.parse_args(args)


def load_hashes(filename="hashes.json"):
    if os.path.exists(filename):
        with open(filename, 'rb') as hashfile:
            hashes = set(json.load(hashfile))
        logging.info('Loaded hashes from %s', filename)
    else:
        hashes = set()
    return hashes


def save_hashes(hashes, filename='hashes.json'):
    logging.info('Dumping hashes to %s', filename)
    with open(filename, 'w') as hashfile:
        json.dump(list(hashes), hashfile, indent=2)


def load_urls(filename='urls.json'):
    if os.path.exists(filename):
        try:
            with open(filename, 'rb') as urlfile:
                urls = set(json.load(urlfile))
            logging.info('Loaded urls from %s', filename)
        except ValueError:  # this usually happens when the file is empty
            urls = set()
    else:
        urls = set()
    return urls


def save_urls(urls, filename='urls.json'):
    logging.info('Dumping past URLs to %s', filename)
    with open(filename, 'w') as urlfile:
        json.dump(list(urls), urlfile, indent=2)


def main():
    resource.setrlimit(resource.RLIMIT_NOFILE, (2048, 2048))
    hashes = set()
    past_urls = set()

    args = setup_args(sys.argv[1:])
    if args.config:
        cfg = config(args, args.config)
    else:
        cfg = config(args, 'maltrieve.cfg')
    cfg.check_proxy()

    hashes = load_hashes('hashes.json')
    past_urls = load_urls('urls.json')

    print "Processing source URLs"

    # TODO: Replace with plugins
    source_urls = {'https://zeustracker.abuse.ch/monitor.php?urlfeed=binaries': process_xml_list_desc,
                   'http://www.malwaredomainlist.com/hostslist/mdl.xml': process_xml_list_desc,
                   'http://malc0de.com/rss/': process_xml_list_desc,
                   'http://vxvault.net/URL_List.php': process_simple_list,
                   'http://urlquery.net/': process_urlquery,
                   'http://support.clean-mx.de/clean-mx/rss?scope=viruses&limit=0%2C64': process_xml_list_title,
                   'http://malwareurls.joxeankoret.com/normal.txt': process_simple_list}
    headers = {'User-Agent': 'Maltrieve'}

    reqs = [grequests.get(url, timeout=60, headers=headers, proxies=cfg.proxy) for url in source_urls]
    source_lists = grequests.map(reqs)

    print "Completed source processing"

    headers['User-Agent'] = cfg.useragent
    malware_urls = set()
    for response in source_lists:
        if hasattr(response, 'status_code') and response.status_code == 200:
            malware_urls.update(source_urls[response.url](response.text))

    if cfg.inputfile:
        with open(cfg.inputfile, 'rb') as f:
            moar_urls = list(f)
        malware_urls.update(moar_urls)

    print "Downloading samples, check log for details"

    malware_urls -= past_urls
    reqs = [grequests.get(url, timeout=60, headers=headers, proxies=cfg.proxy) for url in malware_urls]
    for chunk in chunker(reqs, 32):
        malware_downloads = grequests.map(chunk)
        for each in malware_downloads:
            if not each or each.status_code != 200:
                continue
            if save_malware(each, cfg):
                past_urls.add(each.url)

    print "Completed downloads"

    save_urls(past_urls, 'urls.json')
    save_hashes(hashes, 'hashes.json')


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
