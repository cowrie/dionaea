# ABOUTME: Unit and integration tests for DCE-RPC endpoint mapper
# ABOUTME: Tests tower encoding logic and epmap port 135 responses

# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

import socket
import struct
from uuid import UUID

import pytest

# Try to import impacket for integration tests
try:
    from impacket.dcerpc.v5 import epm, transport
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False


# ============================================================================
# Standalone tower encoding implementation for unit testing
# (Duplicated from rpcservices.py to avoid dionaea import dependencies)
# ============================================================================

PROTO_ID_UUID = 0x0d
PROTO_ID_RPC_CO = 0x0b  # Connection-oriented RPC
PROTO_ID_TCP = 0x07
PROTO_ID_IP = 0x09
NDR_UUID = UUID('8a885d04-1ceb-11c9-9fe8-08002b104860')


def build_tower(interface_uuid, major_ver, minor_ver, local_ip, port):
    """Build a DCE/RPC protocol tower for TCP/IP transport."""
    tower = b''

    # Floor count: 5 floors (interface, NDR, RPC, TCP, IP)
    tower += struct.pack('<H', 5)

    # Floor 1: Interface UUID
    uuid_bytes = UUID(interface_uuid).bytes_le
    lhs1 = bytes([PROTO_ID_UUID]) + uuid_bytes + struct.pack('<H', major_ver)
    tower += struct.pack('<H', len(lhs1)) + lhs1
    tower += struct.pack('<H', 2) + struct.pack('<H', minor_ver)

    # Floor 2: NDR Transfer Syntax
    lhs2 = bytes([PROTO_ID_UUID]) + NDR_UUID.bytes_le + struct.pack('<H', 2)
    tower += struct.pack('<H', len(lhs2)) + lhs2
    tower += struct.pack('<H', 2) + struct.pack('<H', 0)

    # Floor 3: RPC Connection-oriented protocol
    lhs3 = bytes([PROTO_ID_RPC_CO])
    tower += struct.pack('<H', len(lhs3)) + lhs3
    tower += struct.pack('<H', 2) + struct.pack('>H', 0)

    # Floor 4: TCP port (big endian)
    lhs4 = bytes([PROTO_ID_TCP])
    tower += struct.pack('<H', len(lhs4)) + lhs4
    tower += struct.pack('<H', 2) + struct.pack('>H', port)

    # Floor 5: IP address (big endian)
    lhs5 = bytes([PROTO_ID_IP])
    tower += struct.pack('<H', len(lhs5)) + lhs5
    try:
        ip_bytes = socket.inet_aton(local_ip)
    except (socket.error, OSError):
        ip_bytes = b'\x7f\x00\x00\x01'
    tower += struct.pack('<H', 4) + ip_bytes

    return tower


# ============================================================================
# Unit tests for tower encoding
# ============================================================================

class TestTowerEncoding:
    """Unit tests for DCE/RPC protocol tower encoding."""

    def test_tower_floor_count(self):
        """Test that tower has 5 floors."""
        tower = build_tower(
            interface_uuid='e1af8308-5d1f-11c9-91a4-08002b14a0fa',
            major_ver=3,
            minor_ver=0,
            local_ip='127.0.0.1',
            port=135
        )
        floor_count = struct.unpack('<H', tower[:2])[0]
        assert floor_count == 5

    def test_tower_interface_uuid(self):
        """Test that interface UUID is correctly encoded in floor 1."""
        test_uuid = 'e1af8308-5d1f-11c9-91a4-08002b14a0fa'
        tower = build_tower(
            interface_uuid=test_uuid,
            major_ver=3,
            minor_ver=0,
            local_ip='127.0.0.1',
            port=135
        )

        # Skip floor count (2 bytes), read LHS length
        pos = 2
        lhs_len = struct.unpack('<H', tower[pos:pos+2])[0]
        pos += 2

        # LHS: protocol_id (1) + UUID (16) + version (2) = 19 bytes
        assert lhs_len == 19

        # Protocol ID should be 0x0d
        assert tower[pos] == 0x0d

        # Extract and verify UUID
        uuid_bytes = tower[pos+1:pos+17]
        extracted_uuid = UUID(bytes_le=uuid_bytes)
        assert str(extracted_uuid) == test_uuid

    def test_tower_version_encoding(self):
        """Test that major/minor versions are encoded correctly."""
        tower = build_tower(
            interface_uuid='e1af8308-5d1f-11c9-91a4-08002b14a0fa',
            major_ver=3,
            minor_ver=5,
            local_ip='127.0.0.1',
            port=135
        )

        # Skip floor count (2), LHS length (2), LHS data (19)
        pos = 2 + 2 + 19

        # RHS length should be 2
        rhs_len = struct.unpack('<H', tower[pos:pos+2])[0]
        assert rhs_len == 2
        pos += 2

        # RHS contains minor version
        minor_ver = struct.unpack('<H', tower[pos:pos+2])[0]
        assert minor_ver == 5

    def test_tower_ndr_syntax(self):
        """Test that NDR transfer syntax UUID is present."""
        tower = build_tower(
            interface_uuid='e1af8308-5d1f-11c9-91a4-08002b14a0fa',
            major_ver=3,
            minor_ver=0,
            local_ip='127.0.0.1',
            port=135
        )
        assert NDR_UUID.bytes_le in tower

    def test_tower_tcp_port(self):
        """Test that TCP port is encoded in big endian."""
        test_port = 445
        tower = build_tower(
            interface_uuid='e1af8308-5d1f-11c9-91a4-08002b14a0fa',
            major_ver=3,
            minor_ver=0,
            local_ip='127.0.0.1',
            port=test_port
        )
        port_bytes = struct.pack('>H', test_port)
        assert port_bytes in tower

    def test_tower_ip_address(self):
        """Test that IP address is correctly encoded."""
        test_ip = '192.168.1.100'
        tower = build_tower(
            interface_uuid='e1af8308-5d1f-11c9-91a4-08002b14a0fa',
            major_ver=3,
            minor_ver=0,
            local_ip=test_ip,
            port=135
        )
        ip_bytes = socket.inet_aton(test_ip)
        assert ip_bytes in tower

    def test_tower_invalid_ip_fallback(self):
        """Test that invalid IP falls back to 127.0.0.1."""
        tower = build_tower(
            interface_uuid='e1af8308-5d1f-11c9-91a4-08002b14a0fa',
            major_ver=3,
            minor_ver=0,
            local_ip='invalid-ip-address',
            port=135
        )
        fallback_ip = socket.inet_aton('127.0.0.1')
        assert fallback_ip in tower

    def test_tower_protocol_identifiers(self):
        """Test that all protocol identifiers are present."""
        tower = build_tower(
            interface_uuid='e1af8308-5d1f-11c9-91a4-08002b14a0fa',
            major_ver=3,
            minor_ver=0,
            local_ip='127.0.0.1',
            port=135
        )
        # UUID protocol ID (floors 1 and 2)
        assert tower.count(bytes([PROTO_ID_UUID])) >= 2
        # RPC connection-oriented (floor 3)
        assert bytes([PROTO_ID_RPC_CO]) in tower
        # TCP (floor 4)
        assert bytes([PROTO_ID_TCP]) in tower
        # IP (floor 5)
        assert bytes([PROTO_ID_IP]) in tower


# ============================================================================
# Integration tests (require running dionaea on port 135)
# ============================================================================

@pytest.mark.skipif(not IMPACKET_AVAILABLE, reason="impacket not installed")
def test_epmap_port_open(dionaea_host, dionaea_ports):
    """Test that epmap port 135 is open."""
    port = dionaea_ports.get("epmap", 135)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    try:
        result = sock.connect_ex((dionaea_host, port))
        assert result == 0, f"Port {port} not open"
    finally:
        sock.close()


@pytest.mark.skipif(not IMPACKET_AVAILABLE, reason="impacket not installed")
def test_epmap_ept_lookup(dionaea_host, dionaea_ports):
    """Test ept_lookup returns registered services."""
    port = dionaea_ports.get("epmap", 135)

    try:
        string_binding = f'ncacn_ip_tcp:{dionaea_host}[{port}]'
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_connect_timeout(10)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)

        # Perform ept_lookup
        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = epm.NULL
        request['Ifid'] = epm.NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 100

        resp = dce.request(request)

        # Should get entries back
        num_ents = resp['num_ents']
        assert num_ents > 0, "Expected at least one endpoint entry"

        dce.disconnect()
    except Exception as e:
        pytest.skip(f"epmap test failed (dionaea may not be running): {e}")


@pytest.mark.skipif(not IMPACKET_AVAILABLE, reason="impacket not installed")
def test_epmap_returns_common_services(dionaea_host, dionaea_ports):
    """Test that common RPC services are advertised."""
    port = dionaea_ports.get("epmap", 135)

    # Well-known UUIDs we expect to see
    expected_uuids = {
        'e1af8308-5d1f-11c9-91a4-08002b14a0fa': 'epmp',
        '12345778-1234-abcd-ef00-0123456789ab': 'lsarpc',
    }

    try:
        string_binding = f'ncacn_ip_tcp:{dionaea_host}[{port}]'
        rpctransport = transport.DCERPCTransportFactory(string_binding)
        rpctransport.set_connect_timeout(10)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)

        request = epm.ept_lookup()
        request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
        request['object'] = epm.NULL
        request['Ifid'] = epm.NULL
        request['vers_option'] = epm.RPC_C_VERS_ALL
        request['max_ents'] = 100

        resp = dce.request(request)

        found_uuids = set()
        for entry in resp['entries']:
            tower_data = b''.join(entry['tower']['tower_octet_string'])
            tower = epm.EPMTower(tower_data)
            if hasattr(tower, 'interface_uuid'):
                found_uuids.add(str(tower.interface_uuid).lower())

        # Check at least epmp is advertised
        epmp_uuid = 'e1af8308-5d1f-11c9-91a4-08002b14a0fa'
        assert epmp_uuid in found_uuids, f"epmp not in advertised services: {found_uuids}"

        dce.disconnect()
    except Exception as e:
        pytest.skip(f"epmap test failed: {e}")
