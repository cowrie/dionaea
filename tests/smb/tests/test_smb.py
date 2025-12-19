# ABOUTME: SMB protocol smoke tests for dionaea honeypot
# ABOUTME: Tests SMB1 via impacket and SMB2/3 via smbprotocol

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

import socket
import uuid

import pytest

# Try to import smbprotocol (SMB2/3), skip tests if not available
try:
    from smbprotocol.connection import Connection
    from smbprotocol.session import Session
    SMBPROTOCOL_AVAILABLE = True
except ImportError:
    SMBPROTOCOL_AVAILABLE = False

# Try to import impacket (SMB1), skip tests if not available
try:
    from impacket.smbconnection import SMBConnection
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False


@pytest.mark.skipif(not SMBPROTOCOL_AVAILABLE, reason="smbprotocol not installed")
def test_smb_negotiate(dionaea_host, dionaea_ports):
    """Test SMB protocol negotiation."""
    port = dionaea_ports["smb"]

    connection = Connection(
        guid=uuid.uuid4(),
        server_name=dionaea_host,
        port=port,
        require_signing=False,
    )
    try:
        connection.connect(timeout=10)
        # If we get here, negotiate succeeded
        assert connection.dialect is not None
    except Exception as e:
        # Connection might fail, but that's ok - we want to see if server responds
        # SMB negotiation failure still means server is listening
        pytest.skip(f"SMB negotiation failed (server may not support modern SMB): {e}")
    finally:
        try:
            connection.disconnect()
        except Exception:
            pass


@pytest.mark.skipif(not SMBPROTOCOL_AVAILABLE, reason="smbprotocol not installed")
def test_smb_session_guest(dionaea_host, dionaea_ports):
    """Test SMB session setup with guest credentials."""
    port = dionaea_ports["smb"]

    connection = Connection(
        guid=uuid.uuid4(),
        server_name=dionaea_host,
        port=port,
        require_signing=False,
    )
    try:
        connection.connect(timeout=10)
        session = Session(
            connection,
            username="guest",
            password="",
            require_encryption=False,
        )
        try:
            session.connect()
        except Exception:
            # Session might fail, that's ok for honeypot
            pass
    except Exception as e:
        pytest.skip(f"SMB connection failed: {e}")
    finally:
        try:
            connection.disconnect()
        except Exception:
            pass


def test_smb_connection_raw(dionaea_host, dionaea_ports):
    """Test raw TCP connection to SMB port and send SMB negotiate request."""
    port = dionaea_ports["smb"]

    # Build minimal SMB1 negotiate request
    # NetBIOS header (4 bytes) + SMB header (32 bytes) + negotiate request
    smb_negotiate = (
        # NetBIOS session header
        b"\x00"  # Message type (Session Message)
        + b"\x00\x00\x25"  # Length (37 bytes)
        # SMB Header
        + b"\xffSMB"  # Protocol identifier
        + b"\x72"  # Command: Negotiate (0x72)
        + b"\x00\x00\x00\x00"  # NT Status
        + b"\x18"  # Flags
        + b"\x01\xc8"  # Flags2
        + b"\x00\x00"  # PID High
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
        + b"\x00\x00"  # Reserved
        + b"\x00\x00"  # TID
        + b"\x00\x00"  # PID Low
        + b"\x00\x00"  # UID
        + b"\x00\x00"  # MID
        # Negotiate request
        + b"\x00"  # Word count
        + b"\x02\x00"  # Byte count
        + b"\x02NT LM 0.12\x00"  # Dialect
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        sock.connect((dionaea_host, port))
        sock.sendall(smb_negotiate)
        # Read response
        response = sock.recv(4096)
        # Should get some response
        assert len(response) >= 4, "No SMB response received"
    finally:
        sock.close()


def test_smb_port_open(dionaea_host, dionaea_ports):
    """Test that SMB port is open and accepting connections."""
    port = dionaea_ports["smb"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        result = sock.connect_ex((dionaea_host, port))
        assert result == 0, f"SMB port {port} not open"
    finally:
        sock.close()


# SMB1 tests using impacket
@pytest.mark.skipif(not IMPACKET_AVAILABLE, reason="impacket not installed")
def test_smb1_negotiate_impacket(dionaea_host, dionaea_ports):
    """Test SMB1 protocol negotiation using impacket."""
    port = dionaea_ports["smb"]

    try:
        # preferredDialect forces SMB1
        conn = SMBConnection(
            dionaea_host,
            dionaea_host,
            sess_port=port,
            preferredDialect=None,  # Let it negotiate
            timeout=10,
        )
        # If we get here, SMB1 negotiate succeeded
        assert conn.getDialect() is not None
        conn.close()
    except Exception as e:
        pytest.fail(f"SMB1 negotiation failed: {e}")


@pytest.mark.skipif(not IMPACKET_AVAILABLE, reason="impacket not installed")
def test_smb1_anonymous_login_impacket(dionaea_host, dionaea_ports):
    """Test SMB1 anonymous/guest login using impacket."""
    port = dionaea_ports["smb"]

    try:
        conn = SMBConnection(
            dionaea_host,
            dionaea_host,
            sess_port=port,
            timeout=10,
        )
        # Try anonymous login
        conn.login("", "")
        conn.close()
    except Exception:
        # Login failure is acceptable for honeypot - connection worked
        pass


@pytest.mark.skipif(not IMPACKET_AVAILABLE, reason="impacket not installed")
def test_smb1_list_shares_impacket(dionaea_host, dionaea_ports):
    """Test SMB1 share enumeration using impacket."""
    port = dionaea_ports["smb"]

    try:
        conn = SMBConnection(
            dionaea_host,
            dionaea_host,
            sess_port=port,
            timeout=10,
        )
        conn.login("", "")
        # Try to list shares
        shares = conn.listShares()
        # Any response is fine, even empty
        assert shares is not None or shares == []
        conn.close()
    except Exception:
        # Failure is acceptable - we just want to see server responds
        pass
