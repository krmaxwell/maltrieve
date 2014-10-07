```
 _______ _______        _______  ______ _____ _______ _    _ _______
 |  |  | |_____| |         |    |_____/   |   |______  \  /  |______
 |  |  | |     | |_____    |    |    \_ __|__ |______   \/   |______

```

## Maltrieve

Maltrieve originated as a fork of [mwcrawler](https://github.com/ricardo-dias/mwcrawler). It retrieves malware directly from the sources as listed at a number of sites, including:

* [Malc0de](http://malc0de.com/rss)
* [Malware Black List](http://www.malwareblacklist.com/mbl.xml)
* [Malware Domain List](http://www.malwaredomainlist.com/hostslist/mdl.xml)
* [VX Vault](http://vxvault.siri-urz.net/URL_List.php)
* [URLqery](http://urlquery.net/)
* [CleanMX](http://support.clean-mx.de/clean-mx/xmlviruses.php?)

These lists will be implemented if/when they return to activity.

* [NovCon Minotaur](http://minotauranalysis.com/malwarelist-urls.aspx)

Other improvements include:

* Proxy support
* Multithreading for improved performance
* Logging of source URLs
* Multiple user agent support
* Better error handling
* [VxCage](https://github.com/botherder/vxcage) and [Cuckoo Sandbox](http://www.cuckoosandbox.org) support


## Installation

Maltrieve requires the following dependencies:

* Python 2 (2.6 should be sufficient)
* [BeautifulSoup](http://www.crummy.com/software/BeautifulSoup/) version 4
* [feedparser](https://pypi.python.org/pypi/feedparser)
* [python-magic](https://pypi.python.org/pypi/python-magic/)
* [Requests](http://www.python-requests.org)

These can all be found in [requirements.txt](./requirements.txt). These can be installed locally using ```pip install -r requirements.txt```. You may need to prepend that with ```sudo``` if not running in a virtual environment.

## Usage

__Basic execution:__ ```python maltrieve.py```

### Options
```
usage: maltrieve.py [-h] [-p PROXY] [-d DUMPDIR] [-l LOGFILE] [-x] [-c]

optional arguments:
  -h, --help            show this help message and exit
  -p PROXY, --proxy PROXY
                        Define HTTP proxy as address:port
  -d DUMPDIR, --dumpdir DUMPDIR
                        Define dump directory for retrieved files
  -l LOGFILE, --logfile LOGFILE
                        Define file for logging progress
  -x, --vxcage          Dump the file to a VxCage instance running on the
                        localhost
  -c, --cuckoo          Enable cuckoo analysis
```

### Configuration File
Many of Maltrieve's command line options can be specified in ```maltrieve.cfg```.


## License

Released under GPL version 3. See the [LICENSE](./LICENSE) file for full details.


## Known bugs

We list all the bugs we know about (plus some things we know we need to add) at the [Github issues](https://github.com/technoskald/maltrieve/issues) page.


## How you can help

Aside from pull requests, non-developers can open issues on [Github](https://github.com/technoskald/maltrieve). Things we'd really appreciate:

* Bug reports, preferably with error logs
* Suggestions of additional sources for malware lists
* Descriptions of how you use it and ways we can improve it for you

Check the [contributing guide](./CONTRIBUTING.md) for details. If you'd prefer not to open an issue, you can [contact me on Twitter](https://twitter.com/kylemaxwell) or [email](mailto:krmaxwell@gmail.com).
