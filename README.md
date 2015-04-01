[![Stories in Ready](https://badge.waffle.io/krmaxwell/maltrieve.png?label=ready&title=Ready)](https://waffle.io/krmaxwell/maltrieve)
[![Stories in In Progress](https://badge.waffle.io/krmaxwell/maltrieve.png?label=in%20progress&title=In%20Progress)](https://waffle.io/krmaxwell/maltrieve)
```
 _______ _______        _______  ______ _____ _______ _    _ _______
 |  |  | |_____| |         |    |_____/   |   |______  \  /  |______
 |  |  | |     | |_____    |    |    \_ __|__ |______   \/   |______

```

## Maltrieve

Maltrieve originated as a fork of [mwcrawler](https://github.com/ricardo-dias/mwcrawler). It retrieves malware directly from the sources as listed at a number of sites. Currently we crawl the following:

* [Malc0de](http://malc0de.com/rss)
* [Malware Black List](http://www.malwareblacklist.com/mbl.xml)
* [Malware Domain List](http://www.malwaredomainlist.com/hostslist/mdl.xml)
* [VX Vault](http://vxvault.siri-urz.net/URL_List.php)
* [URLquery](http://urlquery.net/)
* [CleanMX](http://support.clean-mx.de/clean-mx/xmlviruses.php?)
* [ZeusTracker](https://zeustracker.abuse.ch/monitor.php?urlfeed=binaries)

These lists will be implemented if/when they return to activity.

* [NovCon Minotaur](http://minotauranalysis.com/malwarelist-urls.aspx)

Other improvements include:

* Proxy support
* Multithreading for improved performance
* Logging of source URLs
* Multiple user agent support
* Better error handling
* [VxCage](https://github.com/botherder/vxcage), [Viper](https://github.com/botherder/viper) and [Cuckoo Sandbox](http://www.cuckoosandbox.org) support


## Installation

Maltrieve requires the following dependencies:

* Python 2 plus header files (2.6 should be sufficient)
* [BeautifulSoup](http://www.crummy.com/software/BeautifulSoup/) version 4
* [feedparser](https://pypi.python.org/pypi/feedparser)
* [python-magic](https://pypi.python.org/pypi/python-magic/)
* [Requests](http://www.python-requests.org)

With the exception of the Python header files, these can all be found in [requirements.txt](./requirements.txt). On Debian-based distributions, run `sudo apt-get install python-dev`. On Red Hat-based distributions, run `sudo yum install python-devel`. After that, just `pip install -e .`.  You may need to prepend that with ```sudo``` if not running in a virtual environment, but using such an environment is highly encouraged.

## Usage

__Basic execution:__ `maltrieve` (if installed normally) or ```python maltrieve.py``` (if just downloaded and run)

### Options
```
usage: maltrieve [-h] [-p PROXY] [-d DUMPDIR] [-l LOGFILE] [-x] [-v] [-c] [-s]

optional arguments:
  -h, --help            show this help message and exit
  -p PROXY, --proxy PROXY
                        Define HTTP proxy as address:port
  -d DUMPDIR, --dumpdir DUMPDIR
                        Define dump directory for retrieved files
  -l LOGFILE, --logfile LOGFILE
                        Define file for logging progress
  -x, --vxcage          Dump the files to a VxCage instance
  -v, --viper           Dump the files to a Viper instance
  -c, --cuckoo          Enable Cuckoo analysis
  -s, --sort_mime       Sort files by MIME type

```

### Configuration File
Many of Maltrieve's command line options can be specified in ```maltrieve.cfg```.

## Automated Execution (Optional)
Cron can be used to automate the execution of Maltrieve. The following example is provided to help get you started. It will create a cron job that will run Maltrieve every day at 2:01 as a standard user. That said, we recommend enhancing this by creating a custom script for production environments. 

### Ubuntu
As a user execute
```
crontab -e
```
If installed normally, add the following to the end of the file.
```
01 02 * * * maltrieve <optional flags>
```
If downloaded to a folder and executed, add the following to the end of the file.
```
01 02 * * * cd </folder/location> && /usr/bin/python maltrieve.py <optional flags>
```
### Redhat
Redhat systems will need to ensure that the user is added to the /etc/cron.allow file. 

## License

Released under GPL version 3. See the [LICENSE](./LICENSE) file for full details.


## Known bugs

We list all the bugs we know about (plus some things we know we need to add) at the [GitHub issues](https://github.com/krmaxwell/maltrieve/issues) page.


## How you can help

Aside from pull requests, non-developers can open issues on [Github](https://github.com/krmaxwell/maltrieve). Things we'd really appreciate:

* Bug reports, preferably with error logs
* Suggestions of additional sources for malware lists
* Descriptions of how you use it and ways we can improve it for you

Check the [contributing guide](./CONTRIBUTING.md) for details.
