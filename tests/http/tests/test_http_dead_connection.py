# ABOUTME: Tests that HTTP response methods handle dead connections gracefully.
# ABOUTME: Verifies send_response, send_header, end_headers don't crash when the client disconnects mid-response.

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2026 Michel
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""
When a client disconnects mid-response, binding.pyx raises ReferenceError
from connection.send() because the underlying C connection object is gone.
The HTTP response methods must handle this gracefully instead of crashing.
"""

import os
import sys
import types
import unittest.mock

# Set up mock modules for dionaea's C extension dependencies before importing http.py
_dionaea_mod = types.ModuleType("dionaea")
_dionaea_mod.__path__ = [os.path.join(os.path.dirname(__file__), '..', '..', '..', 'modules', 'python', 'dionaea')]
_dionaea_mod.ServiceLoader = type("ServiceLoader", (), {})

_core_mod = types.ModuleType("dionaea.core")


class _FakeConnection:
    """Stand-in for binding.pyx connection whose send() raises ReferenceError."""
    pass


_core_mod.connection = _FakeConnection
_core_mod.g_dionaea = unittest.mock.MagicMock()
_core_mod.incident = unittest.mock.MagicMock()

_util_mod = types.ModuleType("dionaea.util")
_util_mod.detect_shellshock = lambda *a, **kw: None

_exc_mod = types.ModuleType("dionaea.exception")
_exc_mod.ServiceConfigError = type("ServiceConfigError", (Exception,), {})

sys.modules["dionaea"] = _dionaea_mod
sys.modules["dionaea.core"] = _core_mod
sys.modules["dionaea.util"] = _util_mod
sys.modules["dionaea.exception"] = _exc_mod

# Now we can import httpd
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'modules', 'python'))
from dionaea.http import httpd  # noqa: E402


def _make_dead_httpd():
    """Create an httpd whose send() raises ReferenceError (dead C connection)."""
    h = httpd.__new__(httpd)
    h.responses = httpd.responses

    def dead_send(data, **kwargs):
        raise ReferenceError("the object requested does not exist")

    h.send = dead_send
    return h


def test_send_response_on_dead_connection():
    h = _make_dead_httpd()
    h.send_response(404)


def test_send_header_on_dead_connection():
    h = _make_dead_httpd()
    h.send_header("Content-Type", "text/html")


def test_end_headers_on_dead_connection():
    h = _make_dead_httpd()
    h.end_headers()
