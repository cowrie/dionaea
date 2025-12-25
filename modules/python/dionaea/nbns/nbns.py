# ABOUTME: NetBIOS Name Service (NBNS) protocol implementation for dionaea honeypot
# ABOUTME: Captures NBNS queries to detect WPAD attacks and NetBIOS reconnaissance
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

logger = logging.getLogger('nbns')
logger.setLevel(logging.DEBUG)


# NBNS Opcodes (RFC 1002)
OPCODE_QUERY = 0
OPCODE_REGISTRATION = 5
OPCODE_RELEASE = 6
OPCODE_WACK = 7
OPCODE_REFRESH = 8

# NBNS Name Types (suffix bytes) - common ones for attack detection
NBNS_SUFFIX_WORKSTATION = 0x00
NBNS_SUFFIX_MESSENGER = 0x03
NBNS_SUFFIX_RAS_SERVER = 0x06
NBNS_SUFFIX_DOMAIN_MASTER = 0x1B
NBNS_SUFFIX_DOMAIN_CONTROLLER = 0x1C
NBNS_SUFFIX_MASTER_BROWSER = 0x1D
NBNS_SUFFIX_BROWSER_ELECTION = 0x1E
NBNS_SUFFIX_FILE_SERVER = 0x20
NBNS_SUFFIX_RAS_CLIENT = 0x21
NBNS_SUFFIX_EXCHANGE = 0x87
NBNS_SUFFIX_MSBROWSE = 0x01  # __MSBROWSE__

# Query types
QTYPE_NB = 0x0020      # NetBIOS name query
QTYPE_NBSTAT = 0x0021  # NetBIOS node status (reconnaissance)

# Query classes
QCLASS_IN = 0x0001

# Names commonly targeted in attacks (LLMNR/NBNS poisoning)
SUSPICIOUS_NAMES = {
    'WPAD': 'Web Proxy Auto-Discovery (Hot Potato/WPAD hijack)',
    'ISATAP': 'Intra-Site Automatic Tunnel (tunnel hijack)',
    'TEREDO': 'Teredo tunneling (tunnel hijack)',
    'PROXY': 'Proxy discovery',
    'DNS': 'DNS server discovery',
    'LDAP': 'LDAP server discovery',
    'KERBEROS': 'Kerberos discovery',
    'MSSQL': 'SQL Server discovery',
    'SQLSERVER': 'SQL Server discovery',
    'EXCHANGE': 'Exchange discovery',
}


def decode_netbios_name(encoded: bytes) -> tuple[str, int]:
    """
    Decode a NetBIOS first-level encoded name.

    NetBIOS names are encoded by taking each nibble of each byte
    and adding 'A' (0x41) to it. So 'A' (0x41) becomes 'EB'.

    Returns (name, suffix_byte) tuple.
    """
    if len(encoded) < 32:
        raise ValueError(f"Encoded name too short: {len(encoded)} bytes")

    decoded = []
    for i in range(0, 32, 2):
        high = encoded[i] - ord('A')
        low = encoded[i + 1] - ord('A')
        char = (high << 4) | low
        decoded.append(char)

    # The name is 15 characters + 1 suffix byte
    # Strip trailing spaces from the name
    name_bytes = bytes(decoded[:15])
    suffix = decoded[15]

    # Decode as ASCII, stripping trailing spaces
    try:
        name = name_bytes.decode('ascii').rstrip(' ')
    except UnicodeDecodeError:
        name = name_bytes.hex()

    return name, suffix


def encode_netbios_name(name: str, suffix: int = NBNS_SUFFIX_WORKSTATION) -> bytes:
    """
    Encode a name using NetBIOS first-level encoding.
    """
    # Pad name to 15 characters
    padded = name.upper().ljust(15)[:15]
    name_bytes = padded.encode('ascii') + bytes([suffix])

    encoded = []
    for byte in name_bytes:
        high = (byte >> 4) + ord('A')
        low = (byte & 0x0F) + ord('A')
        encoded.extend([high, low])

    return bytes(encoded)


def get_suffix_name(suffix: int) -> str:
    """Return human-readable name for NetBIOS suffix byte."""
    suffixes = {
        0x00: 'Workstation',
        0x01: 'MSBrowse',
        0x03: 'Messenger',
        0x06: 'RASServer',
        0x1B: 'DomainMaster',
        0x1C: 'DomainController',
        0x1D: 'MasterBrowser',
        0x1E: 'BrowserElection',
        0x20: 'FileServer',
        0x21: 'RASClient',
        0x87: 'Exchange',
    }
    return suffixes.get(suffix, f'Unknown(0x{suffix:02X})')


def get_qtype_name(qtype: int) -> str:
    """Return human-readable name for query type."""
    qtypes = {
        QTYPE_NB: 'NB',
        QTYPE_NBSTAT: 'NBSTAT',
    }
    return qtypes.get(qtype, f'Unknown(0x{qtype:04X})')


def analyze_query_threat(name: str, suffix: int, qtype: int, opcode: int) -> tuple[str, str]:
    """
    Analyze a query for potential attack indicators.

    Returns (threat_level, description) tuple.
    threat_level: 'info', 'suspicious', 'attack'
    """
    name_upper = name.upper()

    # WPAD is the most common attack vector
    if name_upper == 'WPAD':
        return ('attack', 'WPAD query - Hot Potato/NTLM relay attack indicator')

    # Check for other suspicious names
    if name_upper in SUSPICIOUS_NAMES:
        return ('suspicious', SUSPICIOUS_NAMES[name_upper])

    # NBSTAT queries are reconnaissance
    if qtype == QTYPE_NBSTAT:
        return ('suspicious', 'NBSTAT query - NetBIOS reconnaissance/enumeration')

    # Registration attempts could be poisoning
    if opcode == OPCODE_REGISTRATION:
        return ('suspicious', 'Name registration - potential NBNS poisoning attempt')

    # Domain controller/master queries could indicate lateral movement
    if suffix in (NBNS_SUFFIX_DOMAIN_CONTROLLER, NBNS_SUFFIX_DOMAIN_MASTER):
        return ('suspicious', 'Domain controller/master query - potential AD reconnaissance')

    return ('info', 'Normal NBNS query')


class NBNSPacket:
    """Parser for NetBIOS Name Service packets."""

    def __init__(self, data: bytes):
        self.raw_data = data
        self.parse_errors: list[str] = []

        if len(data) < 12:
            raise ValueError(f"Packet too short: {len(data)} bytes (minimum 12)")

        # Parse header
        self.transaction_id = struct.unpack('!H', data[0:2])[0]
        flags = struct.unpack('!H', data[2:4])[0]

        self.is_response = bool(flags & 0x8000)
        self.opcode = (flags >> 11) & 0x0F
        self.authoritative = bool(flags & 0x0400)
        self.truncated = bool(flags & 0x0200)
        self.recursion_desired = bool(flags & 0x0100)
        self.recursion_available = bool(flags & 0x0080)
        self.broadcast = bool(flags & 0x0010)
        self.rcode = flags & 0x000F

        self.qdcount = struct.unpack('!H', data[4:6])[0]
        self.ancount = struct.unpack('!H', data[6:8])[0]
        self.nscount = struct.unpack('!H', data[8:10])[0]
        self.arcount = struct.unpack('!H', data[10:12])[0]

        # Anomaly detection: unusual counts
        if self.qdcount > 10:
            self.parse_errors.append(f"Unusual question count: {self.qdcount}")
        if self.ancount > 100 or self.nscount > 100 or self.arcount > 100:
            self.parse_errors.append(f"Unusual RR counts: an={self.ancount} ns={self.nscount} ar={self.arcount}")

        # Parse questions
        self.questions: list[tuple[str, int, int, int]] = []
        offset = 12

        for _ in range(self.qdcount):
            if offset >= len(data):
                self.parse_errors.append("Packet truncated in question section")
                break

            # Name length byte
            name_len = data[offset]
            offset += 1

            # Anomaly: name length should be 32 for properly encoded NetBIOS name
            if name_len != 32:
                self.parse_errors.append(f"Unusual name length: {name_len} (expected 32)")

            if offset + name_len + 4 > len(data):
                self.parse_errors.append("Packet truncated after name length")
                break

            # Encoded name
            encoded_name = data[offset:offset + name_len]
            offset += name_len

            # Null terminator
            if offset < len(data) and data[offset] == 0:
                offset += 1

            # Type and class
            if offset + 4 > len(data):
                self.parse_errors.append("Packet truncated before type/class")
                break
            qtype = struct.unpack('!H', data[offset:offset + 2])[0]
            qclass = struct.unpack('!H', data[offset + 2:offset + 4])[0]
            offset += 4

            # Anomaly: unexpected query type
            if qtype not in (QTYPE_NB, QTYPE_NBSTAT):
                self.parse_errors.append(f"Unknown query type: 0x{qtype:04X}")

            # Anomaly: unexpected query class
            if qclass != QCLASS_IN:
                self.parse_errors.append(f"Unknown query class: 0x{qclass:04X}")

            # Decode the name
            try:
                name, suffix = decode_netbios_name(encoded_name)
                self.questions.append((name, suffix, qtype, qclass))
            except ValueError as e:
                self.parse_errors.append(f"Failed to decode name: {e}")
                logger.debug("Failed to decode name: %s (raw: %s)", e, encoded_name.hex())

    def get_opcode_name(self) -> str:
        """Return human-readable opcode name."""
        opcodes = {
            0: 'Query',
            5: 'Registration',
            6: 'Release',
            7: 'WACK',
            8: 'Refresh',
        }
        return opcodes.get(self.opcode, f'Unknown({self.opcode})')

    def has_anomalies(self) -> bool:
        """Check if packet has any parsing anomalies."""
        return len(self.parse_errors) > 0


class NBNSResponse:
    """Builder for NBNS response packets."""

    @staticmethod
    def build_positive_name_query_response(
        transaction_id: int,
        name: str,
        suffix: int,
        ip_address: str,
        ttl: int = 300000
    ) -> bytes:
        """
        Build a positive name query response.

        This makes us respond to NBNS queries, appearing as if we own the name.
        """
        # Flags: Response, Authoritative, Recursion Available
        flags = 0x8500

        # Header
        header = struct.pack('!HHHHHH',
            transaction_id,
            flags,
            0,  # Questions
            1,  # Answers
            0,  # Authority
            0   # Additional
        )

        # Answer section
        encoded_name = encode_netbios_name(name, suffix)
        # Length prefix + encoded name + null terminator
        name_field = bytes([len(encoded_name)]) + encoded_name + b'\x00'

        # Parse IP address
        ip_parts = [int(p) for p in ip_address.split('.')]

        # NB record: flags (2) + address (4) = 6 bytes
        rdata = struct.pack('!HBBBb', 0x0000, *ip_parts)

        answer = name_field + struct.pack('!HHIH',
            QTYPE_NB,     # Type
            QCLASS_IN,    # Class
            ttl,          # TTL
            len(rdata)    # RDLENGTH
        ) + rdata

        return header + answer


class nbnsHandler(connection):
    """Handler for individual NBNS connections."""

    def __init__(self, config: dict[str, Any] | None = None):
        connection.__init__(self, 'udp')
        self.config = config or {}
        self.respond_to_queries = self.config.get('respond', False)
        self.respond_to_names = self.config.get('respond_names', ['WPAD', '*'])

    def handle_established(self):
        self.timeouts.idle = 30
        self.timeouts.sustain = 60

        # Report connection
        i = incident("dionaea.connection.udp.connect")
        i.con = self
        i.report()

    def handle_io_in(self, data: bytes) -> int:
        try:
            packet = NBNSPacket(data)
        except ValueError as e:
            logger.warning("Failed to parse NBNS packet from %s:%s: %s",
                          self.remote.host, self.remote.port, e)
            return len(data)

        # Log the query
        if packet.is_response:
            logger.debug("NBNS response from %s:%s (ignoring)",
                        self.remote.host, self.remote.port)
            return len(data)

        opcode_name = packet.get_opcode_name()

        for name, suffix, qtype, qclass in packet.questions:
            suffix_name = get_suffix_name(suffix)

            # Check for WPAD specifically
            is_wpad = name.upper() == 'WPAD'

            if is_wpad:
                logger.info("WPAD query from %s:%s - potential Hot Potato attack!",
                           self.remote.host, self.remote.port)
            else:
                logger.info("NBNS %s from %s:%s: name=%s<%02X> (%s) type=0x%04X",
                           opcode_name, self.remote.host, self.remote.port,
                           name, suffix, suffix_name, qtype)

            # Report incident
            i = incident("dionaea.modules.python.nbns.query")
            i.con = self
            i.name = name
            i.suffix = suffix
            i.suffix_name = suffix_name
            i.opcode = packet.opcode
            i.opcode_name = opcode_name
            i.qtype = qtype
            i.is_wpad = is_wpad
            i.report()

            # Optionally respond to make us look vulnerable
            if self.respond_to_queries:
                should_respond = False
                for pattern in self.respond_to_names:
                    if pattern == '*' or name.upper() == pattern.upper():
                        should_respond = True
                        break

                if should_respond:
                    logger.info("Responding to NBNS query for %s with our IP %s",
                               name, self.local.host)
                    response = NBNSResponse.build_positive_name_query_response(
                        packet.transaction_id,
                        name,
                        suffix,
                        self.local.host
                    )
                    self.send(response)

        return len(data)

    def handle_timeout_idle(self):
        self.close()
        return False

    def handle_timeout_sustain(self):
        return True

    def handle_disconnect(self):
        return False


class nbnsd(connection):
    """NBNS daemon - listens on UDP 137."""

    shared_config_values = [
        "respond",
        "respond_names",
    ]

    def __init__(self, proto: str = 'udp'):
        connection.__init__(self, proto)
        self.config: dict[str, Any] = {}

    def apply_config(self, config: dict[str, Any]) -> None:
        self.config = config

    def handle_established(self):
        self.timeouts.idle = 30
        self.timeouts.sustain = 120

        # Report connection
        i = incident("dionaea.connection.udp.connect")
        i.con = self
        i.report()

    def handle_io_in(self, data: bytes) -> int:
        """Handle incoming NBNS packet."""
        try:
            packet = NBNSPacket(data)
        except ValueError as e:
            logger.warning("Malformed NBNS packet from %s:%s: %s",
                          self.remote.host, self.remote.port, e)
            # Report malformed packet incident
            i = incident("dionaea.modules.python.nbns.malformed")
            i.con = self
            i.error = str(e)
            i.raw_data = data.hex()
            i.report()
            return len(data)

        # Log any parsing anomalies
        if packet.has_anomalies():
            logger.warning("NBNS packet anomalies from %s:%s: %s",
                          self.remote.host, self.remote.port,
                          '; '.join(packet.parse_errors))

        # Log the query
        if packet.is_response:
            logger.debug("NBNS response from %s:%s (ignoring)",
                        self.remote.host, self.remote.port)
            return len(data)

        opcode_name = packet.get_opcode_name()
        respond_to_queries = self.config.get('respond', False)
        respond_to_names = self.config.get('respond_names', ['WPAD', '*'])

        for name, suffix, qtype, qclass in packet.questions:
            suffix_name = get_suffix_name(suffix)
            qtype_name = get_qtype_name(qtype)

            # Analyze threat level
            threat_level, threat_desc = analyze_query_threat(
                name, suffix, qtype, packet.opcode)

            # Log based on threat level
            if threat_level == 'attack':
                logger.warning("NBNS ATTACK from %s:%s: %s (name=%s<%02X> type=%s)",
                              self.remote.host, self.remote.port, threat_desc,
                              name, suffix, qtype_name)
            elif threat_level == 'suspicious':
                logger.info("NBNS suspicious from %s:%s: %s (name=%s<%02X> type=%s)",
                           self.remote.host, self.remote.port, threat_desc,
                           name, suffix, qtype_name)
            else:
                logger.info("NBNS %s from %s:%s: name=%s<%02X> (%s) type=%s",
                           opcode_name, self.remote.host, self.remote.port,
                           name, suffix, suffix_name, qtype_name)

            # Report incident
            i = incident("dionaea.modules.python.nbns.query")
            i.con = self
            i.name = name
            i.suffix = suffix
            i.suffix_name = suffix_name
            i.opcode = packet.opcode
            i.opcode_name = opcode_name
            i.qtype = qtype
            i.qtype_name = qtype_name
            i.is_wpad = (name.upper() == 'WPAD')
            i.threat_level = threat_level
            i.threat_desc = threat_desc
            i.report()

            # Optionally respond to make us look vulnerable
            if respond_to_queries:
                should_respond = False
                for pattern in respond_to_names:
                    if pattern == '*' or name.upper() == pattern.upper():
                        should_respond = True
                        break

                if should_respond:
                    logger.info("Responding to NBNS query for %s with our IP %s",
                               name, self.local.host)
                    response = NBNSResponse.build_positive_name_query_response(
                        packet.transaction_id,
                        name,
                        suffix,
                        self.local.host
                    )
                    self.send(response)

        return len(data)

    def handle_timeout_idle(self):
        return True

    def handle_timeout_sustain(self):
        return True

    def handle_disconnect(self):
        return False


class NBNSService(ServiceLoader):
    """Service loader for NBNS (NetBIOS Name Service) on UDP 137."""

    name = "nbns"

    @classmethod
    def start(cls, addr: str, iface: str | None = None,
              config: dict[str, Any] | None = None) -> nbnsd:
        daemon = nbnsd()
        if config is not None:
            daemon.apply_config(config)
        daemon.bind(addr, 137, iface=iface)
        daemon.listen()
        logger.info("NBNS service started on %s:137", addr)
        return daemon


class NBNSDatagramService(ServiceLoader):
    """Service loader for NetBIOS Datagram Service on UDP 138."""

    name = "nbns-dgm"

    @classmethod
    def start(cls, addr: str, iface: str | None = None,
              config: dict[str, Any] | None = None) -> nbnsd:
        daemon = nbnsd()
        if config is not None:
            daemon.apply_config(config)
        daemon.bind(addr, 138, iface=iface)
        daemon.listen()
        logger.info("NetBIOS Datagram service started on %s:138", addr)
        return daemon
