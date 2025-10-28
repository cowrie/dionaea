dionaea - catches bugs
======================

[![Build Status](https://ci.dinotools.org/job/dionaea-master/badge/icon)](https://ci.dinotools.org/job/dionaea-master/)

Dionaea is meant to be a nepenthes successor, embedding Python as
scripting language, using libemu to detect shellcodes, supporting
IPv6 and TLS.

Protocols
---------

* blackhole
* epmap
* ftp
* http
* memcache
* mirror
* mqtt
* mssql
* mysql
* pptp
* sip
* smb
* tftp
* upnp

Logging
-------

* fail2ban
* hpfeeds
* log_json
* log_sqlit

Documentation
-------------

* [Documentation](https://dionaea.readthedocs.io/)
* [Source](https://github.com/cowrie/dionaea)
* [Issues](https://github.com/cowrie/dionaea/issues)

Licenses
--------

* dionaea: GPLv2+
* tftp service(modules/python/tftp.py): CNRI Python License (incompatible with GPL)
* parts of ftp service(modules/python/ftp.py): MIT (compatible with GPL)
