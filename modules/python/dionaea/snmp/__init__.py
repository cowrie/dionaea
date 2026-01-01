# ABOUTME: SNMP honeypot module for dionaea - logs community strings and queries
# ABOUTME: Detects brute-force community string attacks and amplification attempts
#
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2025 dionaea developers
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import struct
from typing import Any

from dionaea import ServiceLoader
from dionaea.core import connection, incident

logger = logging.getLogger('snmp')
logger.setLevel(logging.INFO)


# SNMP versions
SNMP_V1 = 0
SNMP_V2C = 1
SNMP_V3 = 3

# SNMP PDU types (context-specific tags)
PDU_GET_REQUEST = 0
PDU_GET_NEXT_REQUEST = 1
PDU_GET_RESPONSE = 2
PDU_SET_REQUEST = 3
PDU_TRAP = 4  # v1
PDU_GET_BULK_REQUEST = 5  # v2c+
PDU_INFORM_REQUEST = 6
PDU_TRAP_V2 = 7

PDU_NAMES = {
    PDU_GET_REQUEST: 'GetRequest',
    PDU_GET_NEXT_REQUEST: 'GetNextRequest',
    PDU_GET_RESPONSE: 'GetResponse',
    PDU_SET_REQUEST: 'SetRequest',
    PDU_TRAP: 'Trap',
    PDU_GET_BULK_REQUEST: 'GetBulkRequest',
    PDU_INFORM_REQUEST: 'InformRequest',
    PDU_TRAP_V2: 'TrapV2',
}

# Common OIDs that attackers query
COMMON_OIDS = {
    '1.3.6.1.2.1.1.1.0': ('sysDescr', 'Linux dionaea 5.4.0 #1 SMP x86_64'),
    '1.3.6.1.2.1.1.2.0': ('sysObjectID', '1.3.6.1.4.1.8072.3.2.10'),
    '1.3.6.1.2.1.1.3.0': ('sysUpTime', 123456),
    '1.3.6.1.2.1.1.4.0': ('sysContact', 'admin@localhost'),
    '1.3.6.1.2.1.1.5.0': ('sysName', 'dionaea'),
    '1.3.6.1.2.1.1.6.0': ('sysLocation', 'Unknown'),
    '1.3.6.1.2.1.1.7.0': ('sysServices', 72),
}

# Default/common community strings attackers try
COMMON_COMMUNITIES = {
    'public', 'private', 'community', 'admin', 'manager', 'secret',
    'cisco', 'write', 'read', 'default', 'snmp', 'root', 'guest',
    'cable-docsis', 'c@t', 'mngt', 'test', 'ilmi', 'ILMI',
}

# Security limits
MAX_VARBINDS = 25          # Limit varbinds to prevent amplification
MAX_COMMUNITY_LEN = 128    # Limit community string length
MAX_OID_COMPONENT = 2**32  # Limit OID component size


def sanitize_for_log(s: str, max_len: int = 64) -> str:
    """Sanitize string for safe logging (prevent log injection)."""
    # Remove control characters and limit length
    sanitized = ''.join(c if c.isprintable() and c not in '\r\n\t' else '?' for c in s)
    if len(sanitized) > max_len:
        sanitized = sanitized[:max_len] + '...'
    return sanitized


def decode_ber_length(data: bytes, offset: int) -> tuple[int, int]:
    """
    Decode BER length field.
    Returns (length, bytes_consumed).
    """
    if offset >= len(data):
        raise ValueError("Unexpected end of data reading length")

    first_byte = data[offset]
    if first_byte < 0x80:
        # Short form: length in single byte
        return first_byte, 1
    elif first_byte == 0x80:
        # Indefinite length (not supported)
        raise ValueError("Indefinite length not supported")
    else:
        # Long form: first byte indicates number of length bytes
        num_bytes = first_byte & 0x7F
        if num_bytes > 4:
            raise ValueError(f"Length field too long: {num_bytes} bytes")
        if offset + 1 + num_bytes > len(data):
            raise ValueError("Unexpected end of data reading length bytes")

        length = 0
        for i in range(num_bytes):
            length = (length << 8) | data[offset + 1 + i]
        return length, 1 + num_bytes


def decode_ber_integer(data: bytes, offset: int) -> tuple[int, int]:
    """
    Decode BER integer.
    Returns (value, total_bytes_consumed).
    """
    if offset >= len(data) or data[offset] != 0x02:
        raise ValueError(f"Expected INTEGER tag (0x02), got 0x{data[offset]:02x}")

    length, len_bytes = decode_ber_length(data, offset + 1)
    value_offset = offset + 1 + len_bytes

    if value_offset + length > len(data):
        raise ValueError("Unexpected end of data reading integer value")

    # Decode as signed integer
    value = int.from_bytes(data[value_offset:value_offset + length], 'big', signed=True)
    return value, 1 + len_bytes + length


def decode_ber_string(data: bytes, offset: int) -> tuple[bytes, int]:
    """
    Decode BER octet string.
    Returns (value, total_bytes_consumed).
    """
    if offset >= len(data) or data[offset] != 0x04:
        raise ValueError(f"Expected OCTET STRING tag (0x04), got 0x{data[offset]:02x}")

    length, len_bytes = decode_ber_length(data, offset + 1)
    value_offset = offset + 1 + len_bytes

    if value_offset + length > len(data):
        raise ValueError("Unexpected end of data reading string value")

    return data[value_offset:value_offset + length], 1 + len_bytes + length


def decode_ber_oid(data: bytes, offset: int) -> tuple[str, int]:
    """
    Decode BER object identifier.
    Returns (oid_string, total_bytes_consumed).
    """
    if offset >= len(data) or data[offset] != 0x06:
        raise ValueError(f"Expected OID tag (0x06), got 0x{data[offset]:02x}")

    length, len_bytes = decode_ber_length(data, offset + 1)
    value_offset = offset + 1 + len_bytes

    if value_offset + length > len(data):
        raise ValueError("Unexpected end of data reading OID value")

    oid_bytes = data[value_offset:value_offset + length]
    if len(oid_bytes) == 0:
        return '', 1 + len_bytes + length

    # First byte encodes first two components
    components = [oid_bytes[0] // 40, oid_bytes[0] % 40]

    # Remaining bytes are variable-length encoded
    i = 1
    while i < len(oid_bytes):
        value = 0
        while i < len(oid_bytes):
            byte = oid_bytes[i]
            value = (value << 7) | (byte & 0x7F)
            i += 1
            if value > MAX_OID_COMPONENT:
                raise ValueError(f"OID component too large: {value}")
            if not (byte & 0x80):
                break
        components.append(value)

    return '.'.join(str(c) for c in components), 1 + len_bytes + length


def encode_ber_length(length: int) -> bytes:
    """Encode length in BER format."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])


def encode_ber_integer(value: int) -> bytes:
    """Encode integer in BER format."""
    if value == 0:
        return bytes([0x02, 0x01, 0x00])

    # Determine byte length needed
    if value > 0:
        byte_len = (value.bit_length() + 8) // 8  # +8 for sign bit
    else:
        byte_len = (value.bit_length() + 9) // 8

    value_bytes = value.to_bytes(byte_len, 'big', signed=True)
    return bytes([0x02]) + encode_ber_length(len(value_bytes)) + value_bytes


def encode_ber_string(value: bytes) -> bytes:
    """Encode octet string in BER format."""
    return bytes([0x04]) + encode_ber_length(len(value)) + value


def encode_ber_oid(oid: str) -> bytes:
    """Encode OID in BER format."""
    parts = [int(p) for p in oid.split('.')]
    if len(parts) < 2:
        parts = [1, 3]  # Default to iso.org

    # First two components encoded in first byte
    encoded = bytes([parts[0] * 40 + parts[1]])

    # Remaining components use variable-length encoding
    for component in parts[2:]:
        if component == 0:
            encoded += bytes([0])
        else:
            # Encode in base-128 with continuation bits
            octets = []
            while component > 0:
                octets.insert(0, component & 0x7F)
                component >>= 7
            # Set continuation bit on all but last
            for i in range(len(octets) - 1):
                octets[i] |= 0x80
            encoded += bytes(octets)

    return bytes([0x06]) + encode_ber_length(len(encoded)) + encoded


def encode_ber_null() -> bytes:
    """Encode NULL in BER format."""
    return bytes([0x05, 0x00])


def encode_ber_sequence(contents: bytes) -> bytes:
    """Encode SEQUENCE in BER format."""
    return bytes([0x30]) + encode_ber_length(len(contents)) + contents


class SNMPPacket:
    """Parser for SNMP packets."""

    def __init__(self, data: bytes):
        self.raw_data = data
        self.version: int = 0
        self.community: str = ''
        self.pdu_type: int = 0
        self.request_id: int = 0
        self.error_status: int = 0
        self.error_index: int = 0
        self.varbinds: list[tuple[str, Any]] = []

        self._parse(data)

    def _parse(self, data: bytes) -> None:
        """Parse SNMP packet."""
        if len(data) < 10:
            raise ValueError(f"Packet too short: {len(data)} bytes")

        # SNMP message is a SEQUENCE
        if data[0] != 0x30:
            raise ValueError(f"Expected SEQUENCE (0x30), got 0x{data[0]:02x}")

        seq_len, len_bytes = decode_ber_length(data, 1)
        offset = 1 + len_bytes

        # Version (INTEGER)
        self.version, consumed = decode_ber_integer(data, offset)
        offset += consumed

        # Community string (OCTET STRING)
        community_bytes, consumed = decode_ber_string(data, offset)
        if len(community_bytes) > MAX_COMMUNITY_LEN:
            raise ValueError(f"Community string too long: {len(community_bytes)} bytes")
        self.community = community_bytes.decode('utf-8', errors='replace')
        offset += consumed

        # PDU (context-specific constructed tag: 0xA0-0xAF)
        if offset >= len(data):
            raise ValueError("Unexpected end of data reading PDU")

        pdu_tag = data[offset]
        # Context-specific tags are 0xA0-0xBF (class bits = 10, constructed bit varies)
        # GetRequest=0xA0, GetNextRequest=0xA1, GetResponse=0xA2, SetRequest=0xA3, etc.
        if (pdu_tag & 0xE0) != 0xA0:
            raise ValueError(f"Expected context-specific tag (0xA0-0xBF), got 0x{pdu_tag:02x}")

        self.pdu_type = pdu_tag & 0x1F
        pdu_len, len_bytes = decode_ber_length(data, offset + 1)
        offset += 1 + len_bytes

        # Request ID (INTEGER)
        self.request_id, consumed = decode_ber_integer(data, offset)
        offset += consumed

        # Error status (INTEGER)
        self.error_status, consumed = decode_ber_integer(data, offset)
        offset += consumed

        # Error index (INTEGER)
        self.error_index, consumed = decode_ber_integer(data, offset)
        offset += consumed

        # Variable bindings (SEQUENCE of SEQUENCE)
        if offset < len(data) and data[offset] == 0x30:
            vb_len, len_bytes = decode_ber_length(data, offset + 1)
            offset += 1 + len_bytes

            # Parse each varbind (with limit to prevent amplification attacks)
            end_offset = offset + vb_len
            while offset < end_offset and len(self.varbinds) < MAX_VARBINDS:
                if data[offset] != 0x30:
                    break
                vb_item_len, len_bytes = decode_ber_length(data, offset + 1)
                offset += 1 + len_bytes

                # OID
                oid, consumed = decode_ber_oid(data, offset)
                offset += consumed

                # Value (could be various types, we just skip it)
                # For requests, it's usually NULL
                self.varbinds.append((oid, None))

                # Skip remaining bytes in this varbind
                while offset < end_offset and data[offset] not in (0x30, 0x00):
                    if data[offset] == 0x05:  # NULL
                        offset += 2
                        break
                    # Skip other value types
                    _, len_bytes = decode_ber_length(data, offset + 1)
                    value_len = 0
                    if offset + 1 + len_bytes < len(data):
                        value_len, _ = decode_ber_length(data, offset + 1)
                    offset += 1 + len_bytes + value_len
                    break

    @property
    def pdu_name(self) -> str:
        return PDU_NAMES.get(self.pdu_type, f'Unknown({self.pdu_type})')

    @property
    def version_string(self) -> str:
        versions = {0: 'v1', 1: 'v2c', 3: 'v3'}
        return versions.get(self.version, f'v{self.version}')


class SNMPService(ServiceLoader):
    """Service loader for SNMP honeypot on UDP 161."""

    name = "snmp"

    @classmethod
    def start(cls, addr: str, iface: str | None = None,
              config: dict[str, Any] | None = None) -> list['snmpd'] | None:
        daemon = snmpd(proto='udp')
        daemon.bind(addr, 161, iface=iface)
        daemon.listen()
        return [daemon]


class snmpd(connection):
    """SNMP daemon - listens on UDP 161."""

    def __init__(self, proto: str = 'udp'):
        logger.debug("snmpd starting")
        connection.__init__(self, proto)

    def handle_established(self) -> None:
        self.timeouts.idle = 30
        self.timeouts.sustain = 120
        self.processors()

        # Report UDP connection for logging
        i = incident("dionaea.connection.udp.connect")
        i.con = self
        i.report()

    def handle_io_in(self, data: bytes) -> int:
        """Handle incoming SNMP packet."""
        logger.debug("Received %d bytes from %s:%s",
                     len(data), self.remote.host, self.remote.port)

        try:
            pkt = SNMPPacket(data)

            # Determine threat level
            threat = 'info'
            if pkt.community in COMMON_COMMUNITIES:
                threat = 'attack'
            elif pkt.pdu_type in (PDU_SET_REQUEST,):
                threat = 'suspicious'

            # Log the request (sanitize to prevent log injection)
            oids = ', '.join(oid for oid, _ in pkt.varbinds[:3])
            if len(pkt.varbinds) > 3:
                oids += f', ... ({len(pkt.varbinds)} total)'

            log_func = logger.warning if threat == 'attack' else logger.info
            log_func("SNMP %s from %s:%s community='%s' %s OIDs=[%s]",
                     pkt.pdu_name, self.remote.host, self.remote.port,
                     sanitize_for_log(pkt.community), pkt.version_string, oids)

            # Report incident
            inc = incident("dionaea.modules.python.snmp.request")
            inc.con = self
            inc.set("version", pkt.version_string)
            inc.set("community", pkt.community)
            inc.set("pdu_type", pkt.pdu_name)
            inc.set("oids", ','.join(oid for oid, _ in pkt.varbinds))
            inc.report()

            # Send response
            if pkt.pdu_type in (PDU_GET_REQUEST, PDU_GET_NEXT_REQUEST, PDU_GET_BULK_REQUEST):
                response = self._build_response(pkt)
                if response:
                    self.send(response)

        except ValueError as e:
            logger.warning("Failed to parse SNMP packet from %s:%s: %s",
                           self.remote.host, self.remote.port, e)
        except Exception as e:
            logger.error("Error handling SNMP packet: %s", e, exc_info=True)

        return len(data)

    def _build_response(self, request: SNMPPacket) -> bytes | None:
        """Build SNMP GetResponse for the request."""
        # Build varbind list with fake values
        varbinds_data = b''
        for oid, _ in request.varbinds:
            if oid in COMMON_OIDS:
                name, value = COMMON_OIDS[oid]
                if isinstance(value, int):
                    value_encoded = encode_ber_integer(value)
                else:
                    value_encoded = encode_ber_string(value.encode('utf-8'))
            else:
                # Return noSuchObject for unknown OIDs
                value_encoded = bytes([0x80, 0x00])  # noSuchObject

            varbind = encode_ber_sequence(encode_ber_oid(oid) + value_encoded)
            varbinds_data += varbind

        varbinds_seq = encode_ber_sequence(varbinds_data)

        # Build PDU
        pdu_contents = (
            encode_ber_integer(request.request_id) +
            encode_ber_integer(0) +  # error-status: noError
            encode_ber_integer(0) +  # error-index
            varbinds_seq
        )

        # GetResponse PDU (context tag 2)
        pdu = bytes([0xA2]) + encode_ber_length(len(pdu_contents)) + pdu_contents

        # Build message
        message_contents = (
            encode_ber_integer(request.version) +
            encode_ber_string(request.community.encode('utf-8')) +
            pdu
        )

        return encode_ber_sequence(message_contents)

    def handle_timeout_idle(self) -> bool:
        self.close()
        return False

    def handle_disconnect(self) -> bool:
        return False
