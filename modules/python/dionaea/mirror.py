# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2006-2009 Michael P. Soulier
# SPDX-FileCopyrightText: 2009  Paul Baecher & Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea import ServiceLoader
from dionaea.core import connection
import logging
from typing import Any

logger = logging.getLogger('mirror')
logger.setLevel(logging.DEBUG)


class MirrorService(ServiceLoader):
    name = "mirror"

    @classmethod
    def start(cls, addr: str, iface: str | None = None, config: dict[str, Any] | None = None) -> 'mirrord':
        daemon = mirrord('tcp', addr, 42, iface)
        return daemon


class mirrorc(connection):
    def __init__(self, peer: 'mirrord') -> None:
        logger.debug("mirror connection %s %s" %
                     (peer.remote.host, peer.local.host))
        connection.__init__(self, peer.transport)
        self.bind(peer.local.host, 0)
        self.connect(peer.remote.host, peer.local.port)
#		self.connect('',peer.local.port)
        self.peer: mirrord = peer

    def handle_established(self) -> None:
        self.peer.peer = self

    def handle_io_in(self, data: bytes) -> int:
        if self.peer:
            self.peer.send(data)
        return len(data)

    def handle_error(self, err: Any) -> None:
        if self.peer:
            self.peer.peer = None  # type: ignore[assignment]
            self.peer.close()

    def handle_disconnect(self) -> bool:
        if self.peer:
            self.peer.close()
        if self.peer:
            self.peer.peer = None  # type: ignore[assignment]
        return False

class mirrord(connection):
    def __init__(self, proto: str | None = None, host: str | None = None, port: int | None = None, iface: str | None = None) -> None:
        connection.__init__(self, proto)
        if host:
            assert port is not None  # For mypy
            self.bind(host, port, iface)
            self.listen()
        self.peer: mirrorc | None = None

    def handle_established(self) -> None:
        self.peer = mirrorc(self)
        self.timeouts.sustain = 60
        self._in.accounting.limit = 100*1024
        self._out.accounting.limit = 100*1024

    def handle_io_in(self, data: bytes) -> int:
        if self.peer:
            self.peer.send(data)
        return len(data)

    def handle_error(self, err: Any) -> None:
        logger.debug("mirrord connection error?, should not happen")
        if self.peer:
            self.peer.peer = None  # type: ignore[assignment]

    def handle_disconnect(self) -> bool:
        if self.peer:
            self.peer.close()
        if self.peer:
            self.peer.peer = None  # type: ignore[assignment]
        return False
