# ABOUTME: Type stub file for dionaea.core C extension module
# ABOUTME: Provides type hints for connection, ihandler, incident, and g_dionaea

from typing import Any

class connection:
    """Base class for network connection handlers"""

    class _Endpoint:
        host: str
        port: int
        hostname: str | None

    class _Timeouts:
        idle: float
        sustain: float
        listen: float

    class _Stream:
        class _Accounting:
            bytes: int
            limit: int

        class _Speed:
            limit: int

        accounting: _Accounting
        speed: _Speed
        throttle: bool

    local: _Endpoint
    remote: _Endpoint
    timeouts: _Timeouts
    status: str
    protocol: str
    transport: str
    _in: _Stream
    _out: _Stream

    def __init__(self, proto: str | None = None) -> None: ...
    def bind(self, host: str, port: int, iface: str | None = None) -> bool: ...
    def connect(self, host: str, port: int) -> None: ...
    def listen(self, backlog: int = 1) -> bool: ...
    def send(self, data: bytes | str) -> None: ...
    def close(self) -> None: ...
    def processors(self) -> None: ...
    def ref(self) -> None: ...
    def unref(self) -> None: ...

    # Handler methods (override in subclass)
    def handle_established(self) -> None: ...
    def handle_io_in(self, data: bytes) -> int: ...
    def handle_io_out(self) -> None: ...
    def handle_disconnect(self) -> bool: ...
    def handle_timeout_idle(self) -> bool: ...
    def handle_timeout_sustain(self) -> bool: ...
    def handle_timeout_listen(self) -> bool: ...
    def handle_error(self, err: Any) -> None: ...
    def handle_origin(self, parent: connection) -> None: ...

class ihandler:
    """Base class for incident handlers"""

    def __init__(self, path: str) -> None: ...
    def handle_incident(self, icd: incident) -> None: ...
    def stop(self) -> None: ...

class incident:
    """Event object with arbitrary attributes"""

    def __init__(self, name: str) -> None: ...
    def report(self) -> None: ...
    def get(self, key: str, default: Any = None) -> Any: ...

    # Common attributes (can have arbitrary attributes assigned)
    con: connection | None
    path: str | None
    url: bytes | str | None
    parent: connection | None
    child: connection | None
    username: str | None
    password: str | None
    command: str | None
    arguments: list[str] | None
    sha256: str | None
    origin: str | None
    origin_filename: str | None

class _Dionaea:
    """System-wide configuration and utilities"""

    def config(self) -> dict[str, Any]: ...
    def getifaddrs(self) -> dict[str, dict[int, list[dict[str, str]]]]: ...

# Global instance
g_dionaea: _Dionaea

# Download log handler function (used in log.py)
def dlhfn(name: str, level: int, pathname: str, lineno: int, msg: str) -> None: ...
