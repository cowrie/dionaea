# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
from typing import Any

from dionaea import ServiceLoader
from dionaea.core import connection
from dionaea.exception import ServiceConfigError


logger = logging.getLogger("blackhole")
logger.setLevel(logging.DEBUG)


class BlackholeService(ServiceLoader):
    name = "blackhole"

    @classmethod
    def start(cls, addr: str, iface: str | None = None, config: dict[str, Any] | None = None) -> list['Blackhole']:
        if config is None:
            config = {}

        services = config.get("services")
        if services is None:
            logger.warning("No services configured")
            return []

        daemons: list[Blackhole] = []

        for service in services:
            protocol = service.get("protocol")
            port = service.get("port")
            if protocol is None:
                protocol = "tcp"

            if port is None:
                logger.warning("port not defined")
                continue
            if not isinstance(port, int):
                logger.warning("port must be integer")
                continue

            daemon = Blackhole(proto=protocol)
            try:
                daemon.apply_config(config)
            except ServiceConfigError as e:
                logger.error(e.msg, *e.args)
                continue

            daemon.bind(addr, port, iface=iface)
            daemon.listen()
            daemons.append(daemon)

        return daemons


class Blackhole(connection):
    def __init__(self, proto: str | None = None) -> None:
        logger.debug("start blackhole")
        connection.__init__(self, proto)

    def apply_config(self, config: dict[str, Any] | None) -> None:
        pass

    def handle_established(self) -> None:
        self.timeouts.idle = 10
        self.processors()

    def handle_io_in(self, data: bytes) -> int:
        return len(data)

    def handle_timeout_idle(self) -> bool:
        logger.debug("%r handle_timeout_idle", self)
        self.close()
        return False
