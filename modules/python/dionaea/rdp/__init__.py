# ABOUTME: RDP honeypot service loader for dionaea.
# ABOUTME: Registers the RDP service and starts listeners on port 3389.

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger('RDP')

try:
    from dionaea import ServiceLoader
    from dionaea.core import connection
    from .rdp import rdpd

    class rdpd_connection(rdpd, connection):
        """RDP connection combining the protocol handler with dionaea's connection class."""

        def __init__(self) -> None:
            connection.__init__(self, "tcp")
            rdpd.__init__(self)

    class RDPService(ServiceLoader):
        name = "rdp"

        @classmethod
        def start(cls, addr: str, iface: str | None = None, config: dict[str, Any] | None = None) -> rdpd_connection:
            daemon = rdpd_connection()
            daemon.apply_config(config or {})
            port = (config or {}).get("port", 3389)
            daemon.bind(addr, port, iface=iface)
            daemon.listen()
            return daemon

except ImportError:
    # Running outside dionaea (e.g., unit tests) — ServiceLoader not available
    pass
