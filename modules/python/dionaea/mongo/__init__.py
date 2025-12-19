# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2017 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

from typing import Any

from dionaea import ServiceLoader
from .mongo import mongod


class MongoService(ServiceLoader):
    name = "mongo"

    @classmethod
    def start(cls, addr: str, iface: str | None = None, config: dict[str, Any] | None = None) -> mongod:
        daemon = mongod()
        daemon.apply_config(config or {})
        daemon.bind(addr, 27017, iface=iface)
        daemon.listen()
        return daemon
