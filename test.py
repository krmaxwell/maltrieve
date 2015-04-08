import os
import subprocess

import maltrieve
import markdown
import requests


def test_basic_args():
    args = maltrieve.setup_args(['-l', 'testlog', '-p', '127.0.0.1:8080', '-d', '/opt/'])
    assert args.logfile == 'testlog'
    assert args.proxy == '127.0.0.1:8080'
    assert args.dumpdir == '/opt/'


def test_saving_args():
    args = maltrieve.setup_args(['-v', '-x', '-c', '-s'])
    assert args.viper
    assert args.vxcage
    assert args.cuckoo
    assert args.sort_mime


def test_read_alt_config():
    args = maltrieve.setup_args(['--config', 'maltrieve-test.cfg'])
    assert args.config == "maltrieve-test.cfg"


def test_config_args():
    args = maltrieve.setup_args(['-l', 'testlog', '-p', '127.0.0.1:8080', '-d', '/tmp/mwtest'])
    cfg = maltrieve.config(args, 'maltrieve-test.cfg')
    assert cfg.logfile == 'testlog'
    test_proxy = {'http': '127.0.0.1:8080'}
    assert cmp(cfg.proxy, test_proxy) == 0
    assert cfg.dumpdir == '/tmp/mwtest'


def test_inputfile():
    args = maltrieve.setup_args(['-i', 'test-input'])
    cfg = maltrieve.config(args, 'maltrieve-test.cfg')
    assert cfg.inputfile == 'test-input'


def test_alt_config():
    args = maltrieve.setup_args(['--config', 'maltrieve-test.cfg'])
    cfg = maltrieve.config(args, args.config)
    assert cfg.dumpdir == 'archive-test'
    assert cfg.logfile == 'maltrieve-test.log'
    test_ua = {'User-Agent': 'Test-Agent'}
    assert cmp(cfg.useragent, test_ua) == 0
    test_proxy = {'http': '127.0.0.1:3128'}
    assert cmp(cfg.proxy, test_proxy) == 0
    assert cfg.black_list == ['text/html', 'text/plain']
    assert cfg.white_list == ['application/pdf', 'application/x-dosexec']
    assert cfg.crits == 'http://127.0.0.1:8080'
    assert cfg.crits_user == 'maltrieve'
    assert cfg.crits_key == 'YOUR_API_KEY_HERE'
    assert cfg.crits_source == 'maltrieve'
    assert cfg.inputfile is None


def test_create_default_dumpdir():
    args = maltrieve.setup_args(['-d', '/'])
    cfg = maltrieve.config(args, 'maltrieve-test.cfg')
    assert cfg.dumpdir == '/tmp/malware'


def test_create_default_dumpdir_when_specified_doesnt_exist():
    args = maltrieve.setup_args(['-d', '/_nope_'])
    cfg = maltrieve.config(args, 'maltrieve-test.cfg')
    assert cfg.dumpdir == '/tmp/malware'


def test_parse_simple_list():
    source = requests.get('http://xwell.org/assets/maltrieve-test.txt').text
    assert maltrieve.process_simple_list(source) == \
        set(['http://example.org/mylist', 'http://example.com/yourlist'])


def test_parse_xml_list():
    source = requests.get('http://xwell.org/assets/maltrieve-test-list.xml').text
    assert maltrieve.process_xml_list_title(source) == \
        set(['http://example.org/mylist', 'http://example.com/yourlist'])


def test_parse_xml_desc():
    source = requests.get('http://xwell.org/assets/maltrieve-test-desc.xml').text
    assert maltrieve.process_xml_list_desc(source) == \
        set(['http://example.org/mylist', 'http://example.com/yourlist'])


def test_load_hashes(hashfile='test-load-hashes.json'):
    assert maltrieve.load_hashes(hashfile) == \
        set(['d41d8cd98f00b204e9800998ecf8427e'])


def test_save_hashes():
    hashes = set(['d41d8cd98f00b204e9800998ecf8427e'])
    maltrieve.save_hashes(hashes, 'test-save-hashes.json')
    test_load_hashes('test-save-hashes.json')


def test_empty_urls():
    fname = 'maltrieve.py'
    assert maltrieve.load_urls(fname) == set()


def test_load_urls(urlfile='test-load-urls.json'):
    assert maltrieve.load_urls(urlfile) == \
        set(['http://example.com/badurl'])


def test_save_urls():
    urls = set(['http://example.com/badurl'])
    maltrieve.save_urls(urls, 'test-save-urls.json')
    test_load_urls('test-save-urls.json')


def test_save_blacklist():
    args = maltrieve.setup_args(['--config', 'maltrieve-test.cfg'])
    cfg = maltrieve.config(args, args.config)
    r = requests.get('http://xwell.org')
    assert maltrieve.save_malware(r, cfg) is False


def test_save_whitelist_fail():
    args = maltrieve.setup_args(['--config', 'maltrieve-test.cfg'])
    cfg = maltrieve.config(args, args.config)
    r = requests.get('http://xwell.org/assets/images/dodecahedron.png')
    assert maltrieve.save_malware(r, cfg) is False


def test_save_whitelist_pass():
    args = maltrieve.setup_args(['--config', 'maltrieve-test.cfg'])
    cfg = maltrieve.config(args, args.config)
    r = requests.get('http://xwell.org/assets/docs/test.pdf')
    assert maltrieve.save_malware(r, cfg)
    assert os.access('archive-test/b9ff662486d448da7b60ba6234867c65', os.F_OK)


def test_sort_mime():
    args = maltrieve.setup_args(['--config', 'maltrieve-test.cfg'])
    cfg = maltrieve.config(args, args.config)
    cfg.sort_mime = True
    r = requests.get('http://xwell.org/assets/docs/test.pdf')
    assert maltrieve.save_malware(r, cfg)
    assert os.access('archive-test/application_pdf/b9ff662486d448da7b60ba6234867c65', os.F_OK)


def test_README_links():
    markdown.markdownFromFile(input='README.md', output='README.html')
    assert subprocess.call(['linkchecker', '--check-extern', 'README.html']) == 0
