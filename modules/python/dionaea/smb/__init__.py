# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter & Mark Schloesser
# SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

from typing import Any
from dionaea import ServiceLoader
from dionaea.exception import ServiceConfigError
from .smb import epmapper, smbd, smblog


class EPMAPService(ServiceLoader):
    name = "epmap"

    @classmethod
    def start(cls, addr: str, iface: str | None = None, config: dict[str, Any] | None = None) -> 'epmapper':
        daemon = epmapper()
        daemon.bind(addr, 135, iface=iface)
        daemon.listen()
        return daemon


class SMBService(ServiceLoader):
    name = "smb"

    @classmethod
    def start(cls, addr: str, iface: str | None = None, config: dict[str, Any] | None = None) -> 'smbd | None':
        daemon = smbd()
        try:
            daemon.apply_config(config=config or {})
        except ServiceConfigError as e:
            smblog.error(e.msg, *e.args)
            return None
        daemon.bind(addr, daemon.config.port, iface=iface)
        daemon.listen()
        return daemon
