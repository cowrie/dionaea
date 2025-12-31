# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea.core import dlhfn, g_dionaea
import logging

handler: 'DionaeaLogHandler | None' = None
logger: logging.Logger | None = None

# Map string level names to logging constants
LEVEL_MAP = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL,
}


class DionaeaLogHandler(logging.Handler):
    def __init__(self, level: int = logging.INFO) -> None:
        logging.Handler.__init__(self, level)

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)
        dlhfn(record.name, record.levelno, record.pathname, record.lineno, msg)


def new() -> None:
    global logger
    global handler

    # Read log level from config, default to INFO
    module_config = g_dionaea.config().get("module", {}).get("python", {})
    level_name = module_config.get("loglevel", "info").lower()
    level = LEVEL_MAP.get(level_name, logging.INFO)

    logger = logging.getLogger('')
    logger.setLevel(level)
    handler = DionaeaLogHandler(level)
    logger.addHandler(handler)


def start() -> None:
    pass


def stop() -> None:
    assert logger is not None  # For mypy
    assert handler is not None  # For mypy
    logger.removeHandler(handler)
