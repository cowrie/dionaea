# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea.core import dlhfn
import logging

handler: 'DionaeaLogHandler | None' = None
logger: logging.Logger | None = None


class DionaeaLogHandler(logging.Handler):
    def __init__(self) -> None:
        logging.Handler.__init__(self, logging.DEBUG)

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)
        dlhfn(record.name, record.levelno, record.pathname, record.lineno, msg)


def new() -> None:
    global logger
    global handler
    logger = logging.getLogger('')
    logger.setLevel(logging.DEBUG)
    handler = DionaeaLogHandler()
    logger.addHandler(handler)


def start() -> None:
    pass


def stop() -> None:
    assert logger is not None  # For mypy
    assert handler is not None  # For mypy
    logger.removeHandler(handler)
