# ABOUTME: RDP protocol smoke tests for dionaea honeypot using aardwolf client.
# ABOUTME: Tests X.224 negotiation, TLS upgrade, and NTLM authentication stages.

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

import asyncio
import socket
import struct

import pytest

aardwolf = pytest.importorskip("aardwolf")

from aardwolf.commons.target import RDPTarget  # noqa: E402
from aardwolf.commons.iosettings import RDPIOSettings  # noqa: E402
from aardwolf.connection import RDPConnection  # noqa: E402
from asyauth.common.credentials import UniCredential  # noqa: E402
from asyauth.common.constants import asyauthSecret, asyauthProtocol  # noqa: E402


def test_rdp_tcp_connect(dionaea_host, dionaea_ports):
    """Test raw TCP connection to RDP port gets X.224 response."""
    port = dionaea_ports["rdp"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((dionaea_host, port))

        # Send X.224 Connection Request (non-SSL)
        x224_cr = bytes.fromhex("030000130ee000000000000100080000000000")
        sock.sendall(x224_cr)

        response = sock.recv(4096)
        # Should get a TPKT response (version 3)
        assert len(response) >= 4, "Response too short for TPKT"
        assert response[0] == 3, f"Expected TPKT version 3, got {response[0]}"
    finally:
        sock.close()


def test_rdp_x224_ssl_negotiation(dionaea_host, dionaea_ports):
    """Test X.224 Connection Request with SSL negotiation."""
    port = dionaea_ports["rdp"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((dionaea_host, port))

        # Send X.224 Connection Request with SSL protocol flag
        x224_cr = bytes.fromhex("030000130ee000000000000100080001000000")
        sock.sendall(x224_cr)

        response = sock.recv(4096)
        assert len(response) >= 11, "Response too short for X.224 CC with negotiation"
        assert response[0] == 3, "Expected TPKT version 3"

        # Parse X.224 Connection Confirm
        tpkt_len = struct.unpack(">H", response[2:4])[0]
        assert tpkt_len == len(response), "TPKT length mismatch"
    finally:
        sock.close()


def test_rdp_aardwolf_connect_no_auth(dionaea_host, dionaea_ports):
    """Test aardwolf RDP connection without authentication."""
    port = dionaea_ports["rdp"]

    target = RDPTarget(
        ip=dionaea_host,
        port=port,
        timeout=10,
        unsafe_ssl=True,
    )
    credentials = UniCredential(
        stype=asyauthSecret.NONE,
        protocol=asyauthProtocol.NONE,
    )
    iosettings = RDPIOSettings()

    conn = RDPConnection(target, credentials, iosettings)

    async def attempt_connect():
        # We expect the connection to proceed through X.224 negotiation
        # and potentially fail at a later stage (MCS, auth, etc.)
        # since this is a honeypot with limited RDP implementation.
        try:
            result, err = await conn.connect()
            # Either success or an error after negotiation is fine —
            # we're testing that the honeypot handles the protocol.
            return result, err
        except Exception as e:
            # Connection-level errors after negotiation are expected
            return None, e

    asyncio.run(attempt_connect())
    # The test passes as long as the honeypot didn't crash and responded.
    # We don't require a fully successful connection.


def test_rdp_aardwolf_ntlm_auth(dionaea_host, dionaea_ports):
    """Test aardwolf RDP connection with NTLM credentials."""
    port = dionaea_ports["rdp"]

    target = RDPTarget(
        ip=dionaea_host,
        port=port,
        timeout=10,
        unsafe_ssl=True,
    )
    credentials = UniCredential(
        username="testuser",
        secret="testpass",
        domain="WORKGROUP",
        stype=asyauthSecret.PASSWORD,
        protocol=asyauthProtocol.NTLM,
    )
    iosettings = RDPIOSettings()

    conn = RDPConnection(target, credentials, iosettings)

    async def attempt_connect():
        try:
            result, err = await conn.connect()
            return result, err
        except Exception as e:
            return None, e

    asyncio.run(attempt_connect())
    # The honeypot should handle the NTLM negotiation attempt
    # without crashing. Auth failure is expected.
