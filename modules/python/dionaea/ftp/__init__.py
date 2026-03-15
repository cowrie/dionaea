# ABOUTME: FTP protocol handler package for the dionaea honeypot.
# ABOUTME: Provides FTP service with RFC 4217 STARTTLS support.

# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import logging

from dionaea import ServiceLoader
from dionaea.exception import ServiceConfigError

from .server import FTPd

logger = logging.getLogger('ftp')


class FTPService(ServiceLoader):
    name = "ftp"

    @classmethod
    def start(cls, addr, iface=None, config=None):
        daemon = FTPd()
        try:
            daemon.apply_config(config or {})
        except ServiceConfigError as e:
            logger.error(e.msg, *e.args)
            return
        port = (config or {}).get("port", 21)
        daemon.bind(addr, port, iface=iface)
        daemon.listen()
        return daemon
