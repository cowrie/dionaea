# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2015 Tan Kean Siong
# SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

import logging
from typing import Any

from dionaea import ServiceLoader
from dionaea.exception import ServiceConfigError
from .pptp import pptpd

logger = logging.getLogger('pptp')


class PPTPService(ServiceLoader):
    name = "pptp"

    @classmethod
    def start(cls, addr: str, iface: str | None = None, config: dict[str, Any] | None = None) -> pptpd | None:
        daemon = pptpd()
        try:
            daemon.apply_config(config)
        except ServiceConfigError as e:
            logger.error(e.msg, *e.args)
            return None
        daemon.bind(addr, 1723, iface=iface)
        daemon.listen()
        return daemon
