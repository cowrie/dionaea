# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2016-2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

# ABOUTME: Custom exception classes for dionaea.
# ABOUTME: Includes loader, service config, and connection error types.

from typing import Any

class DionaeaError(Exception):
    def __init__(self, msg: str, *args: Any) -> None:
        self.msg: str = msg
        self.args: tuple[Any, ...] = args

    def __str__(self) -> str:
        return self.msg % self.args


class LoaderError(DionaeaError):
    pass


class ServiceConfigError(DionaeaError):
    pass


class DionaeaConnectionError(DionaeaError):
    """Base class for connection-related errors. Named to avoid shadowing builtin ConnectionError."""
    def __init__(self, connection: Any = None, error_id: int | None = None) -> None:
        self.connection: Any = connection
        self.error_id: int | None = error_id


class ConnectionDNSTimeout(DionaeaConnectionError):
    def __str__(self) -> str:
        return "Timeout resolving the hostname/domain: %s" % (
            self.connection.remote.hostname
        )


class ConnectionUnreachable(DionaeaConnectionError):
    def __str__(self) -> str:
        hostname = self.connection.remote.hostname
        if hostname is None or hostname == "":
            hostname = self.connection.remote.host

        return "Could not connect to host(s): %s:%d" % (
            hostname,
            self.connection.remote.port
        )


class ConnectionNoSuchDomain(DionaeaConnectionError):
    def __str__(self) -> str:
        return "Could not resolve the domain: %s" % (
            self.connection.remote.hostname
        )


class ConnectionTooMany(DionaeaConnectionError):
    def __str__(self) -> str:
        return "Too many connections"


class ConnectionUnknownError(DionaeaConnectionError):
    def __str__(self) -> str:
        assert self.error_id is not None  # For mypy
        return "Unknown error occurred: error_id=%d" % (
            self.error_id
        )
