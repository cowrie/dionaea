# ABOUTME: Pytest conftest providing a mock dionaea.core for FTP unit tests.
# ABOUTME: Allows testing FTP logic without the Rust PyO3 runtime.

# SPDX-FileCopyrightText: 2026 Cowrie <cowrie@cowrie.org>
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Cowrie-Commercial

import os
import sys
import types


class MockNodeInfo:
    """Minimal stand-in for connection.local / connection.remote."""

    def __init__(self):
        self.host = "127.0.0.1"
        self.port = 0
        self.hostname = None


class MockConnection:
    """Minimal stand-in for dionaea.core.connection."""

    def __init__(self, proto="tcp"):
        self.proto = proto
        self.protocol_name = ""
        self.local = MockNodeInfo()
        self.remote = MockNodeInfo()
        self.status = "established"
        self._sent = []
        self._closed = False
        self._tls_started = False
        self._processors_called = False
        self.shared_config_values = ()

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        self._sent.append(data)

    def close(self):
        self._closed = True

    def start_tls(self):
        self._tls_started = True

    def processors(self):
        self._processors_called = True

    def bind(self, host, port, iface=None):
        self.local.host = host
        self.local.port = port

    def listen(self, backlog=1):
        pass

    def connect(self, host, port):
        self.remote.host = host
        self.remote.port = port

    def ref(self):
        pass

    def unref(self):
        pass


class MockIncident:
    """Minimal stand-in for dionaea.core.incident."""

    _all_incidents = []

    def __init__(self, origin=None):
        self.origin = origin
        self._reported = False
        self._attrs = {}

    def __setattr__(self, name, value):
        if name in ("origin", "_reported", "_attrs"):
            object.__setattr__(self, name, value)
        else:
            self._attrs[name] = value

    def __getattr__(self, name):
        try:
            return self._attrs[name]
        except KeyError:
            raise AttributeError(name)

    def report(self):
        self._reported = True
        MockIncident._all_incidents.append(self)


def _install_mock_core():
    """Install mock dionaea.core in sys.modules before any ftp imports."""
    if "dionaea.core" not in sys.modules:
        core_mod = types.ModuleType("dionaea.core")
        core_mod.connection = MockConnection
        core_mod.incident = MockIncident
        sys.modules["dionaea.core"] = core_mod


# Install immediately at conftest load time (before test collection imports)
_install_mock_core()

# Ensure the real dionaea package is on the path
_modules_python = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "modules", "python"
)
_modules_python = os.path.normpath(_modules_python)
if _modules_python not in sys.path:
    sys.path.insert(0, _modules_python)
