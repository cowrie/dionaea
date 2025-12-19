# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2015 Tan Kean Siong
# SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

from typing import Any

from dionaea import ServiceLoader
from dionaea.core import g_dionaea
from .upnp import upnpd


class UPNPService(ServiceLoader):
    name = "upnp"

    @classmethod
    def start(cls, addr: str, iface: str | None = None, config: dict[str, Any] | None = None) -> upnpd:
        daemon = upnpd()
        daemon.apply_config(config or {})
        daemon.bind(addr, 1900, iface=iface)
        daemon.listen()
        return daemon
