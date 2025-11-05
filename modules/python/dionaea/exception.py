# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2016-2018 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

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


class ConnectionError(DionaeaError):
    def __init__(self, connection: Any = None, error_id: int | None = None) -> None:
        self.connection: Any = connection
        self.error_id: int | None = error_id


class ConnectionDNSTimeout(ConnectionError):
    def __str__(self) -> str:
        return "Timeout resolving the hostname/domain: %s" % (
            self.connection.remote.hostname
        )


class ConnectionUnreachable(ConnectionError):
    def __str__(self) -> str:
        hostname = self.connection.remote.hostname
        if hostname is None or hostname == "":
            hostname = self.connection.remote.host

        return "Could not connect to host(s): %s:%d" % (
            hostname,
            self.connection.remote.port
        )


class ConnectionNoSuchDomain(ConnectionError):
    def __str__(self) -> str:
        return "Could not resolve the domain: %s" % (
            self.connection.remote.hostname
        )


class ConnectionTooMany(ConnectionError):
    def __str__(self) -> str:
        return "Too many connections"


class ConnectionUnknownError(ConnectionError):
    def __str__(self) -> str:
        assert self.error_id is not None  # For mypy
        return "Unknown error occured: error_id=%d" % (
            self.error_id
        )
