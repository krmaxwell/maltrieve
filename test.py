import maltrieve
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
