# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2010 Tan Kean Siong
# SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

from typing import Any

from dionaea import ServiceLoader
from .mssql import mssqld


class MSSQLService(ServiceLoader):
    name = "mssql"

    @classmethod
    def start(cls, addr: str, iface: str | None = None, config: dict[str, Any] | None = None) -> mssqld:
        daemon = mssqld()
        daemon.apply_config(config or {})
        daemon.bind(addr, 1433, iface=iface)
        daemon.listen()
        return daemon
