# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2010-2011 Mark Schloesser
# SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

from typing import Any
from dionaea.core import ihandler, incident
from dionaea.util import md5file, sha512file
from dionaea import IHandlerLoader

import logging
import uuid
import struct
import socket
from urllib.parse import urlparse

try:
    import magic  # type: ignore[import-not-found]
except Exception:
    def filetype(fpath: str) -> str:
        return ''
else:
    def filetype(fpath: str) -> str:
        try:
            mc = magic.Magic()
            ftype = mc.from_file(fpath)
        except Exception:
            ftype = ''
        return ftype

logger = logging.getLogger('submit_http')
logger.setLevel(logging.DEBUG)


class SubmitHTTPHandlerLoader(IHandlerLoader):
    name = "submit_http"

    @classmethod
    def start(cls, config: dict[str, Any] | None = None) -> 'handler':
        return handler("*", config=config)


class submithttp_report:
    def __init__(self, sha512h: str, md5: str, filepath: str) -> None:
        self.sha512h: str = sha512h
        self.md5h: str = md5
        self.filepath: str = filepath
        self.saddr: str = ''
        self.sport: str = ''
        self.daddr: str = ''
        self.dport: str = ''
        self.download_url: str = ''
        self.filetype: str = ''
        self.filename: str = ''


class handler(ihandler):
    def __init__(self, path: str, config: dict[str, Any] | None = None) -> None:
        logger.debug("%s ready!" % (self.__class__.__name__))
        ihandler.__init__(self, path)

        if config is None:
            config = {}
        self.backendurl: str | None = config.get("url")
        self.email: str | None = config.get("email")
        self.user: str = config.get("user", "")
        self.passwd: str = config.get("pass", "")
        self.cookies: dict[str, submithttp_report] = {}

        # heartbeats
        #dinfo = g_dionaea.version()
        #self.software = 'dionaea {0} {1}/{2} - {3} {4}'.format(
        #    dinfo['dionaea']['version'],
        #    dinfo['compiler']['os'],
        #    dinfo['compiler']['arch'],
        #    dinfo['compiler']['date'],
        #    dinfo['compiler']['time'],
        #)

    def handle_incident(self, icd: incident) -> None:
        pass

    def handle_incident_dionaea_download_complete_unique(self, icd: incident) -> None:
        cookie = str(uuid.uuid4())

        i = incident("dionaea.upload.request")
        i._url = self.backendurl

        assert icd.file is not None  # For mypy
        i.sha512 = sha512file(icd.file)
        i.md5 = md5file(icd.file)
        i.email = self.email
        i.user = self.user
        i.set('pass', self.passwd)

        assert i.sha512 is not None  # For mypy
        assert i.md5 is not None  # For mypy
        mr = submithttp_report(i.sha512, i.md5, icd.file)

        if hasattr(icd, 'con') and icd.con is not None:
            i.source_host = str(
                struct.unpack('!I', socket.inet_aton(icd.con.remote.host))[0]
            )
            i.source_port = str(icd.con.remote.port)
            i.target_host = str(
                struct.unpack('!I', socket.inet_aton(icd.con.local.host))[0]
            )
            i.target_port = str(icd.con.local.port)
            assert i.source_host is not None and i.source_port is not None  # For mypy
            assert i.target_host is not None and i.target_port is not None  # For mypy
            mr.saddr, mr.sport, mr.daddr, mr.dport = i.source_host, i.source_port, i.target_host, i.target_port
        if hasattr(icd, 'url') and icd.url is not None:
            i.url = icd.url
            i.trigger = icd.url
            url_str = icd.url.decode() if isinstance(icd.url, bytes) else icd.url
            try:
                i.filename = urlparse(url_str).path.split('/')[-1]
                mr.filename = i.filename or ''
            except Exception:
                pass
            mr.download_url = url_str

        i.filetype = filetype(icd.file)
        mr.filetype = i.filetype

        i._callback = "dionaea.modules.python.submithttp.result"
        i._userdata = cookie

        self.cookies[cookie] = mr
        i.report()

    # handle agains in the same way
    handle_incident_dionaea_download_complete_again = handle_incident_dionaea_download_complete_unique

    def handle_incident_dionaea_modules_python_submithttp_result(self, icd: incident) -> None:
        assert icd.path is not None  # For mypy
        with open(icd.path, mode="rb") as fh:
            c = fh.read()
        logger.info(f"submithttp result: {c!r}")

        assert icd._userdata is not None  # For mypy
        cookie = icd._userdata
        mr = self.cookies[cookie]

        # does backend want us to upload?
        if b'UNKNOWN' in c or b'S_FILEREQUEST' in c:
            i = incident("dionaea.upload.request")
            i._url = self.backendurl

            i.sha512 = mr.sha512h
            i.md5 = mr.md5h
            i.email = self.email
            i.user = self.user
            i.set('pass', self.passwd)

            i.set('file://data', mr.filepath)

            i.source_host = mr.saddr
            i.source_port = mr.sport
            i.target_host = mr.daddr
            i.target_port = mr.dport
            i.url = mr.download_url
            i.trigger = mr.download_url

            i.filetype = mr.filetype
            i.filename = mr.filename

            i._callback = "dionaea.modules.python.submithttp.uploadresult"
            i._userdata = cookie

            i.report()
        else:
            del self.cookies[cookie]

    def handle_incident_dionaea_modules_python_submithttp_uploadresult(self, icd: incident) -> None:
        assert icd.path is not None  # For mypy
        with open(icd.path, mode="rb") as fh:
            c = fh.read()
        logger.info(f"submithttp uploadresult: {c!r}")

        assert icd._userdata is not None  # For mypy
        del self.cookies[icd._userdata]
