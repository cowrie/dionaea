# ABOUTME: RDP honeypot service registration for dionaea.
# ABOUTME: Registers the RDP service with dionaea's service loader.

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2025 Cowrie <cowrie@cowrie.org>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial

from typing import Any

try:
    from dionaea import ServiceLoader
    from dionaea.exception import ServiceConfigError
    from .rdp import rdpd, rdplog

    class RDPService(ServiceLoader):
        """RDP honeypot service."""

        name = "rdp"

        @classmethod
        def start(
            cls, addr: str, iface: str | None = None, config: dict[str, Any] | None = None
        ) -> rdpd | None:
            daemon = rdpd()
            try:
                daemon.apply_config(config=config)
            except ServiceConfigError as e:
                rdplog.error(e.msg, *e.args)
                return None
            daemon.bind(addr, daemon.config.port, iface=iface)
            daemon.listen()
            return daemon

except ImportError:
    # Running outside dionaea (e.g., unit tests) — ServiceLoader not available
    pass
