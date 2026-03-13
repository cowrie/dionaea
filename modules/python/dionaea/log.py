# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import annotations

from dionaea.core import dlhfn
import logging

# Register TRACE level (below DEBUG=10, matches Rust tracing::trace)
TRACE = 5
logging.addLevelName(TRACE, "TRACE")

handler: 'DionaeaLogHandler | None' = None
logger: logging.Logger | None = None


class DionaeaLogHandler(logging.Handler):
    def __init__(self) -> None:
        logging.Handler.__init__(self, TRACE)

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)
        dlhfn(record.name, record.levelno, record.pathname, record.lineno, msg)


def new() -> None:
    global logger
    global handler

    # Pass everything through to Rust tracing — filtering happens there
    logger = logging.getLogger('')
    logger.setLevel(TRACE)
    handler = DionaeaLogHandler()
    logger.addHandler(handler)


def start() -> None:
    pass


def stop() -> None:
    assert logger is not None  # For mypy
    assert handler is not None  # For mypy
    logger.removeHandler(handler)
